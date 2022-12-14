package dk.rmgroup.keycloak.storage.api.itcn;

import static dk.rmgroup.keycloak.storage.api.itcn.ItcnApiUserStorageProviderConstants.CONFIG_KEY_ACTIVE_DIRECTORY_URL;
import static dk.rmgroup.keycloak.storage.api.itcn.ItcnApiUserStorageProviderConstants.CONFIG_KEY_ALLOW_UPDATE_UPN_DOMAINS;
import static dk.rmgroup.keycloak.storage.api.itcn.ItcnApiUserStorageProviderConstants.CONFIG_KEY_GROUP_MAP;
import static dk.rmgroup.keycloak.storage.api.itcn.ItcnApiUserStorageProviderConstants.CONFIG_KEY_LOGIN_URL;
import static dk.rmgroup.keycloak.storage.api.itcn.ItcnApiUserStorageProviderConstants.CONFIG_KEY_PASSWORD;
import static dk.rmgroup.keycloak.storage.api.itcn.ItcnApiUserStorageProviderConstants.CONFIG_KEY_USERNAME;

import java.io.BufferedReader;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.net.HttpURLConnection;
import java.net.URL;
import java.net.URLConnection;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Date;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.stream.Collectors;
import java.util.stream.IntStream;

import org.jboss.logging.Logger;
import org.json.JSONArray;
import org.json.JSONObject;
import org.keycloak.component.ComponentModel;
import org.keycloak.component.ComponentValidationException;
import org.keycloak.models.GroupModel;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.KeycloakSessionFactory;
import org.keycloak.models.KeycloakSessionTask;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserModel;
import org.keycloak.models.UserProvider;
import org.keycloak.models.utils.KeycloakModelUtils;
import org.keycloak.provider.ProviderConfigProperty;
import org.keycloak.provider.ProviderConfigurationBuilder;
import org.keycloak.storage.UserStorageProviderFactory;
import org.keycloak.storage.UserStorageProviderModel;
import org.keycloak.storage.user.ImportSynchronization;
import org.keycloak.storage.user.SynchronizationResult;

public class ItcnApiUserStorageProviderFactory
    implements UserStorageProviderFactory<ItcnApiUserStorageProvider>, ImportSynchronization {

  protected final List<ProviderConfigProperty> configMetadata;

  private static final Logger logger = Logger.getLogger(ItcnApiUserStorageProviderFactory.class);

  public ItcnApiUserStorageProviderFactory() {
    configMetadata = ProviderConfigurationBuilder.create()
        .property()
        .name(CONFIG_KEY_LOGIN_URL)
        .label("Login endpoint URL")
        .type(ProviderConfigProperty.STRING_TYPE)
        .helpText("URL to the Login endpoint")
        .add()
        .property()
        .name(CONFIG_KEY_USERNAME)
        .label("Username")
        .type(ProviderConfigProperty.STRING_TYPE)
        .helpText("Username used for Login endpoint")
        .add()
        .property()
        .name(CONFIG_KEY_PASSWORD)
        .label("Password")
        .type(ProviderConfigProperty.STRING_TYPE)
        .helpText("Password used for Login endpoint")
        .add()
        .property()
        .name(CONFIG_KEY_ACTIVE_DIRECTORY_URL)
        .label("ActiveDirectory endpoint URL")
        .type(ProviderConfigProperty.STRING_TYPE)
        .helpText("URL to the ActiveDirectory endpoint")
        .add()
        .property()
        .name(CONFIG_KEY_ALLOW_UPDATE_UPN_DOMAINS)
        .label("Allow taking over users from UPN domains")
        .type(ProviderConfigProperty.STRING_TYPE)
        .helpText(
            "Allow taking over federation for users whose UPN is one of the domains in this comma separated list. Note that this may overwrite data on existing users in the database!")
        .add()
        .property()
        .name(CONFIG_KEY_GROUP_MAP)
        .label("Group map")
        .type(ProviderConfigProperty.STRING_TYPE)
        .helpText(
            "Specify the group map using a json object like this: {\"ITCN Group 1\": \"/Keycoak Group 1\", \"ITCN Group 2\": \"/Keycoak Group 2\"}, remember that group names are case sensitive!")
        .add()
        .build();
  }

  @Override
  public String getId() {
    return "itcn";
  }

  @Override
  public List<ProviderConfigProperty> getConfigProperties() {
    return configMetadata;
  }

  @Override
  public ItcnApiUserStorageProvider create(KeycloakSession ksession, ComponentModel model) {
    return new ItcnApiUserStorageProvider();
  }

  @Override
  public SynchronizationResult sync(KeycloakSessionFactory sessionFactory, String realmId,
      UserStorageProviderModel model) {
    return syncImpl(sessionFactory, realmId, model);
  }

  @Override
  public SynchronizationResult syncSince(Date lastSync, KeycloakSessionFactory sessionFactory, String realmId,
      UserStorageProviderModel model) {
    return syncImpl(sessionFactory, realmId, model);
  }

  @Override
  public void validateConfiguration(KeycloakSession session, RealmModel realm, ComponentModel config)
      throws ComponentValidationException {
    if (!config.contains(CONFIG_KEY_LOGIN_URL)) {
      throw new ComponentValidationException("Login endpoint URL is required!");
    }
    if (!config.contains(CONFIG_KEY_USERNAME)) {
      throw new ComponentValidationException("Username is required!");
    }
    if (!config.contains(CONFIG_KEY_PASSWORD)) {
      throw new ComponentValidationException("Password is required!");
    }
    if (!config.contains(CONFIG_KEY_ACTIVE_DIRECTORY_URL)) {
      throw new ComponentValidationException("ActiveDirectory endpoint URL is required!");
    }

    GroupMapConfig groupMapConfig = GetGroupMapConfig(realm, config);

    if (groupMapConfig.errors.size() > 0) {
      throw new ComponentValidationException(
          String.format("Errors found in Group map: %s", String.join(", ", groupMapConfig.errors)));
    }

    UserStorageProviderFactory.super.validateConfiguration(session, realm, config);
  }

  private SynchronizationResult syncImpl(KeycloakSessionFactory sessionFactory, String realmId,
      UserStorageProviderModel model) {
    String token;
    try {
      token = getToken(model.get(CONFIG_KEY_LOGIN_URL), model.get(CONFIG_KEY_USERNAME), model.get(CONFIG_KEY_PASSWORD));
    } catch (Exception e) {
      logger.errorf(e,
          "Error getting token for federation provider '%s'. Please check Login endpoint URL and username and password!",
          model.getName());
      SynchronizationResult synchronizationResult = new SynchronizationResult();
      synchronizationResult.setFailed(1);
      return synchronizationResult;
    }
    List<ItcnApiUser> apiUsers;
    try {
      apiUsers = getUsers(model.get(CONFIG_KEY_ACTIVE_DIRECTORY_URL), token);
    } catch (Exception e) {
      logger.errorf(e, "Error getting users for federation provider '%s'. Please check ActiveDirectory endpoint url!",
          model.getName());
      SynchronizationResult synchronizationResult = new SynchronizationResult();
      synchronizationResult.setFailed(1);
      return synchronizationResult;
    }

    String allowUpdateUpnDomainsCommaSeparated = model.get(CONFIG_KEY_ALLOW_UPDATE_UPN_DOMAINS);

    List<String> allowUpdateUpnDomains = null;
    if (allowUpdateUpnDomainsCommaSeparated != null && allowUpdateUpnDomainsCommaSeparated.length() > 0) {
      allowUpdateUpnDomains = Arrays.stream(allowUpdateUpnDomainsCommaSeparated.split(",")).map(d -> d.trim())
          .collect(Collectors.toList());
    }

    GroupMapConfig groupMapConfig = GetGroupMapConfig(sessionFactory, realmId, model);

    return importApiUsers(sessionFactory, realmId, model, apiUsers, allowUpdateUpnDomains, groupMapConfig.groupMap);
  }

  class GroupMapConfig {
    private Map<String, GroupModel> groupMap = new HashMap<String, GroupModel>();

    private List<String> errors = new ArrayList<String>();

    public Map<String, GroupModel> getGroupMap() {
      return groupMap;
    }

    public List<String> getErrors() {
      return errors;
    }

    public void setProperties(GroupMapConfig groupMapConfig) {
      groupMap = groupMapConfig.groupMap;
      errors = groupMapConfig.errors;
    }
  }

  private GroupMapConfig GetGroupMapConfig(KeycloakSessionFactory sessionFactory, final String realmId,
      ComponentModel config) {
    final GroupMapConfig groupMapConfig = new GroupMapConfig();
    KeycloakModelUtils.runJobInTransaction(sessionFactory, session -> {
      RealmModel realm = session.realms().getRealm(realmId);
      groupMapConfig.setProperties(GetGroupMapConfig(realm, config));
    });
    return groupMapConfig;
  }

  private GroupMapConfig GetGroupMapConfig(RealmModel realm, ComponentModel config) {
    GroupMapConfig groupMapConfig = new GroupMapConfig();
    Map<String, GroupModel> groupMap = groupMapConfig.groupMap;
    List<String> errors = groupMapConfig.errors;

    if (config.contains(CONFIG_KEY_GROUP_MAP)) {
      String json = config.get(CONFIG_KEY_GROUP_MAP);

      try {
        Map<String, Object> jsonMap = new JSONObject(json).toMap();
        jsonMap.forEach((k, v) -> {
          try {
            GroupModel kcGroup = KeycloakModelUtils.findGroupByPath(realm, v.toString());
            if (kcGroup != null) {
              groupMap.put(k, kcGroup);
            } else {
              String errorMessage = String.format("Keycloak group '%s' not found.", v);
              logger.error(errorMessage);
              errors.add(errorMessage);
            }
          } catch (Exception e) {
            String errorMessage = String.format("Error getting Keycloak group '%s'. '%s'", v, e.getMessage());
            logger.error(errorMessage, e);
            errors.add(errorMessage);
          }
        });
      } catch (Exception e) {
        String errorMessage = String.format("Error in group map JSON '%s'. '%s'", json, e.getMessage());
        logger.error(errorMessage, e);
        errors.add(errorMessage);
      }
    }

    return groupMapConfig;
  }

  private SynchronizationResult importApiUsers(KeycloakSessionFactory sessionFactory, final String realmId,
      final ComponentModel fedModel, List<ItcnApiUser> apiUsers, List<String> allowUpdateUpnDomains,
      Map<String, GroupModel> groupMap) {
    final SynchronizationResult syncResult = new SynchronizationResult();

    final String fedId = fedModel.getId();

    final Set<String> apiUsersUpnSet = apiUsers.stream().map(u -> u.getUpn().toLowerCase()).distinct()
        .collect(Collectors.toSet());

    KeycloakModelUtils.runJobInTransaction(sessionFactory, new KeycloakSessionTask() {

      @Override
      public void run(KeycloakSession session) {
        try {
          RealmModel realm = session.realms().getRealm(realmId);
          UserProvider userProvider = session.users();
          List<UserModel> usersToRemove = userProvider.getUsersStream(realm)
              .filter(u -> fedId.equals(u.getFederationLink()) && !apiUsersUpnSet.contains(u.getUsername()))
              .collect(Collectors.toList());
          for (final UserModel user : usersToRemove) {
            try {
              userProvider.removeUser(realm, user);
              syncResult.increaseRemoved();
            } catch (Exception e) {
              logger.errorf(e, "Error removing non existing users user with username '%s' in federation provider '%s'",
                  user.getUsername(), fedModel.getName());
              syncResult.increaseFailed();
            }
          }
        } catch (Exception e) {
          logger.errorf(e, "Error getting users to remove in federation provider '%s'", fedModel.getName());
        }
      }
    });

    for (final ItcnApiUser apiUser : apiUsers) {
      try {
        KeycloakModelUtils.runJobInTransaction(sessionFactory, new KeycloakSessionTask() {

          @Override
          public void run(KeycloakSession session) {
            RealmModel realm = session.realms().getRealm(realmId);
            UserProvider userProvider = session.users();
            UserModel importedUser;
            UserModel existingLocalUser = userProvider.getUserByUsername(realm, apiUser.getUpn());
            if (existingLocalUser == null) {
              importedUser = userProvider.addUser(realm, apiUser.getUpn());
            } else {
              if (fedId.equals(existingLocalUser.getFederationLink())) {
                importedUser = existingLocalUser;
              } else if (allowUpdateUpnDomains != null) {
                String upn = apiUser.getUpn();
                if (!allowUpdateUpnDomains.stream().anyMatch(domain -> upn.endsWith("@" + domain))) {
                  logger.warnf(
                      "User with UPN '%s' is not updated during sync as he already exists in Keycloak database but is not linked to federation provider '%s' and UPN domain does not match any of '%s'",
                      apiUser.getUpn(), fedModel.getName(), String.join(", ", allowUpdateUpnDomains));
                  syncResult.increaseFailed();
                  return;
                }
                importedUser = existingLocalUser;
              } else {
                logger.warnf(
                    "User with UPN '%s' is not updated during sync as he already exists in Keycloak database but is not linked to federation provider '%s'",
                    apiUser.getUpn(), fedModel.getName());
                syncResult.increaseFailed();
                return;
              }
            }
            importedUser.setFederationLink(fedId);
            importedUser.setEmail(apiUser.getEmail());
            importedUser.setEmailVerified(true);
            importedUser.setFirstName(apiUser.getFirstName());
            importedUser.setLastName(apiUser.getSurName());
            importedUser.setSingleAttribute("mobile", apiUser.getMobilePhone());
            importedUser.setEnabled(true);

            String[] apiUserGroups = apiUser.getGroups();

            HashSet<String> groupIds = new HashSet<String>();

            if (groupMap != null && groupMap.size() > 0 && apiUserGroups != null && apiUserGroups.length > 0) {
              for (String apiUserGroup : apiUserGroups) {
                if (groupMap.containsKey(apiUserGroup)) {
                  GroupModel kcGroup = groupMap.get(apiUserGroup);
                  groupIds.add(kcGroup.getId());
                  if (!importedUser.isMemberOf(kcGroup)) {
                    importedUser.joinGroup(kcGroup);
                  }
                }
              }
              importedUser.getGroupsStream().filter(g -> {
                return !groupIds.contains(g.getId());
              }).forEach(g -> {
                importedUser.leaveGroup(g);
              });
            }

            if (existingLocalUser == null) {
              syncResult.increaseAdded();
            } else {
              syncResult.increaseUpdated();
            }
          }
        });
      } catch (Exception e) {
        logger.error("Failed during import user from LDAP", e);
        syncResult.increaseFailed();
      }
    }

    return syncResult;
  }

  private static String getToken(String loginUrl, String username, String password) throws Exception {
    URL url = new URL(loginUrl);
    URLConnection con = url.openConnection();
    HttpURLConnection http = (HttpURLConnection) con;
    http.setRequestMethod("POST");
    http.setDoInput(true);
    http.setDoOutput(true);

    byte[] out = String.format("{\"username\":\"%s\",\"password\":\"%s\"}", username, password)
        .getBytes(StandardCharsets.UTF_8);
    int length = out.length;

    http.setFixedLengthStreamingMode(length);
    http.setRequestProperty("Content-Type", "application/json; charset=UTF-8");
    http.connect();
    try (OutputStream os = http.getOutputStream()) {
      os.write(out);
    }
    try (InputStream inputStream = http.getInputStream()) {
      String text = new BufferedReader(
          new InputStreamReader(inputStream, StandardCharsets.UTF_8))
          .lines()
          .collect(Collectors.joining("\n"));
      JSONObject jsonObject = new JSONObject(text);
      return jsonObject.getString("token");
    }
  }

  private static List<ItcnApiUser> getUsers(String usersUrl, String token) throws Exception {
    URL url = new URL(usersUrl);
    URLConnection con = url.openConnection();
    HttpURLConnection http = (HttpURLConnection) con;
    http.setRequestMethod("GET");
    http.setRequestProperty("Authorization", String.format("Bearer %s", token));
    http.setDoOutput(true);

    try (InputStream inputStream = http.getInputStream()) {
      String text = new BufferedReader(
          new InputStreamReader(inputStream, StandardCharsets.UTF_8))
          .lines()
          .collect(Collectors.joining("\n"));
      JSONObject jsonObject = new JSONObject(text);
      JSONArray jsonArray = jsonObject.getJSONArray("value");
      List<ItcnApiUser> users = IntStream.range(0, jsonArray.length()).mapToObj(i -> {
        JSONObject o = jsonArray.getJSONObject(i);
        String[] groups = new String[] {};
        if (o.has("Groups") && !o.isNull("Groups")) {
          JSONArray gr = o.getJSONArray("Groups");
          groups = IntStream.range(0, gr.length()).mapToObj(j -> gr.getString(j)).toArray(String[]::new);
        }
        return new ItcnApiUser(o.getString("UPN"), o.getString("Email"), o.optString("FirstName"),
            o.optString("SurName"), o.optString("MobilePhone"), groups);
      }).collect(Collectors.toList());
      return users;
    }
  }
}
