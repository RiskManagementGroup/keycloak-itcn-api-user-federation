package dk.rmgroup.keycloak.storage.api.itcn;

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
import java.util.Objects;
import java.util.Set;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.stream.Collectors;
import java.util.stream.IntStream;

import org.jboss.logging.Logger;
import org.json.JSONArray;
import org.json.JSONException;
import org.json.JSONObject;
import org.keycloak.component.ComponentModel;
import org.keycloak.component.ComponentValidationException;
import org.keycloak.email.EmailException;
import org.keycloak.email.EmailSenderProvider;
import org.keycloak.models.GroupModel;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.KeycloakSessionFactory;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserModel;
import org.keycloak.models.UserProvider;
import org.keycloak.models.utils.KeycloakModelUtils;
import org.keycloak.provider.ProviderConfigProperty;
import org.keycloak.provider.ProviderConfigurationBuilder;
import org.keycloak.storage.UserStorageProviderFactory;
import org.keycloak.storage.UserStorageProviderModel;
import org.keycloak.storage.managers.UserStorageSyncManager;
import org.keycloak.storage.user.ImportSynchronization;
import org.keycloak.storage.user.SynchronizationResult;

import static dk.rmgroup.keycloak.storage.api.itcn.ItcnApiUserStorageProviderConstants.CONFIG_KEY_ACTIVE_DIRECTORY_URL;
import static dk.rmgroup.keycloak.storage.api.itcn.ItcnApiUserStorageProviderConstants.CONFIG_KEY_ALLOW_UPDATE_UPN_DOMAINS;
import static dk.rmgroup.keycloak.storage.api.itcn.ItcnApiUserStorageProviderConstants.CONFIG_KEY_GROUP_MAP;
import static dk.rmgroup.keycloak.storage.api.itcn.ItcnApiUserStorageProviderConstants.CONFIG_KEY_LOGIN_URL;
import static dk.rmgroup.keycloak.storage.api.itcn.ItcnApiUserStorageProviderConstants.CONFIG_KEY_ONLY_USE_GROUPS_IN_GROUP_MAP;
import static dk.rmgroup.keycloak.storage.api.itcn.ItcnApiUserStorageProviderConstants.CONFIG_KEY_PASSWORD;
import static dk.rmgroup.keycloak.storage.api.itcn.ItcnApiUserStorageProviderConstants.CONFIG_KEY_USERNAME;

public class ItcnApiUserStorageProviderFactory
    implements UserStorageProviderFactory<ItcnApiUserStorageProvider>, ImportSynchronization {

  protected final List<ProviderConfigProperty> configMetadata;

  private static final Logger logger = Logger.getLogger(ItcnApiUserStorageProviderFactory.class);

  private static final int USER_REMOVE_PAGE_SIZE = 100;

  private static final int USER_IMPORT_PAGE_SIZE = 100;

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
        .property()
        .name(
            CONFIG_KEY_ONLY_USE_GROUPS_IN_GROUP_MAP)
        .label("Only handle groups in group map")
        .type(ProviderConfigProperty.BOOLEAN_TYPE)
        .helpText(
            "Disregard any and all groups not mentioned above")
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

    GroupMapConfig groupMapConfig = GetGroupMapConfig(session, realm, config);

    if (!groupMapConfig.errors.isEmpty()) {
      throw new ComponentValidationException(
          String.format("Errors found in Group map: %s", String.join(", ", groupMapConfig.errors)));
    }

    // For some reason enabled is set to 't' when saving configuration.
    // This will cause provider and linked users to get disabled and subsequent
    // periodic syncs not to run,
    // so we work around that by setting enabled to "true" in the
    // validateConfiguration.
    // This was not necessary prior to version 21
    String enabled = config.getConfig().getFirst("enabled");

    if ("t".equals(enabled)) {
      logger.debug("enabled is set to 't'. Will change it to 'true' as a workaround");
      config.getConfig().put("enabled", Arrays.asList("true"));
    }
  }

  @Override
  public void onUpdate(KeycloakSession session, RealmModel realm, ComponentModel oldModel, ComponentModel newModel) {
    // Periodic sync is normally only refreshed if there are changes to sync
    // intervals.
    // This means that other changes to the config is not applied to the periodic
    // sync,
    // until a restart or a change to the sync intervals.
    // So this code ensures that we refresh periodic sync upon any change to the
    // config
    if (!Objects.equals(oldModel.getConfig(), newModel.getConfig())) {
      UserStorageProviderModel oldProvider = new UserStorageProviderModel(oldModel);
      UserStorageProviderModel newProvider = new UserStorageProviderModel(newModel);

      // Only refresh periodic sync here if the intervals have not changed, otherwise
      // it would be done twice.
      // It might not do any harm, but there is no need to make Keycloak do more work
      // than necesary
      if (oldProvider.getChangedSyncPeriod() == newProvider.getChangedSyncPeriod()
          && oldProvider.getFullSyncPeriod() == newProvider.getFullSyncPeriod()) {
        logger.debug("Ensure periodic sync is refreshed if there are any changes to the config");
        UserStorageSyncManager.notifyToRefreshPeriodicSync(session, realm, newProvider, false);
      }
    }
  }

  private SynchronizationResult syncImpl(KeycloakSessionFactory sessionFactory, String realmId,
      UserStorageProviderModel model) {
    ItcnAdminEventLogger adminEventLogger = new ItcnAdminEventLogger(sessionFactory, realmId);

    KeycloakSession session = sessionFactory.create();

    RealmModel realm = session.realms().getRealm(realmId);

    EmailSenderProvider emailSenderProvider = session.getProvider(EmailSenderProvider.class);

    try {
      adminEventLogger.Log(String.format("user-storage/%s/sync-starting", model.getName()),
          String.format("Starting ITCN user synchronization for '%s'", model.getName()));
    } catch (Exception e) {
      logger.errorf(e, "ITCN error logging");
    }

    SynchronizationResult synchronizationResult = new SynchronizationResult();
    List<String> errors = new ArrayList<>();

    boolean hasImportFinished = false;

    try {
      String token = getToken(model.get(CONFIG_KEY_LOGIN_URL), model.get(CONFIG_KEY_USERNAME),
          model.get(CONFIG_KEY_PASSWORD));

      try {
        List<ItcnApiUser> apiUsers = getItcnApiUsers(model.get(CONFIG_KEY_ACTIVE_DIRECTORY_URL), token);

        try {
          String allowUpdateUpnDomainsCommaSeparated = model.get(CONFIG_KEY_ALLOW_UPDATE_UPN_DOMAINS);

          List<String> allowUpdateUpnDomains = null;
          if (allowUpdateUpnDomainsCommaSeparated != null && allowUpdateUpnDomainsCommaSeparated.length() > 0) {
            allowUpdateUpnDomains = Arrays.stream(allowUpdateUpnDomainsCommaSeparated.split(",")).map(d -> d.trim())
                .collect(Collectors.toList());
          }

          GroupMapConfig groupMapConfig = GetGroupMapConfig(sessionFactory, realmId, model);

          ItcnApiUserResult result = importApiUsers(sessionFactory, realmId, model, apiUsers, allowUpdateUpnDomains,
              groupMapConfig.groupMap);

          synchronizationResult = result.synchronizationResult;
          errors = result.errors;

          hasImportFinished = true;
        } catch (Exception e) {
          logger.errorf(e, "Error importing api users for federation provider '%s'!",
              model.getName());
          errors.add(String.format("Error importing api users for federation provider '%s'! Exception:<br/>%s",
              model.getName(), getErrorMessage(e)));
          synchronizationResult.setFailed(1);
        }
      } catch (Exception e) {
        logger.errorf(e, "Error getting users for federation provider '%s'. Please check ActiveDirectory endpoint url!",
            model.getName());
        errors.add(String.format(
            "Error getting users for federation provider '%s'. Please check ActiveDirectory endpoint url! Exception:<br/>%s",
            model.getName(), getErrorMessage(e)));
        synchronizationResult.setFailed(1);
      }
    } catch (Exception e) {
      logger.errorf(e,
          "Error getting token for federation provider '%s'. Please check Login endpoint URL and username and password!",
          model.getName());
      errors.add(String.format(
          "Error getting token for federation provider '%s'. Please check Login endpoint URL and username and password! Exception:<br/>%s",
          model.getName(), getErrorMessage(e)));
      synchronizationResult.setFailed(1);
    }

    if (hasImportFinished) {
      adminEventLogger.Log(String.format("user-storage/%s/sync-finished", model.getName()), synchronizationResult);

      if (synchronizationResult.getFailed() > 0) {
        try {
          String body = String.format(
              "Error during user synchronization for federation provider '%s' in realm: '%s'. %s users failed syncing. Errors:<br/><br/>%s",
              model.getName(), realm.getName(), synchronizationResult.getFailed(), String.join("<br/><br/>", errors));

          emailSenderProvider.send(realm.getSmtpConfig(), "log.rmgroup@f24.com", "Error in user sync", body, body);
        } catch (EmailException ex) {
          logger.errorf(ex, "Failed to send email");
        }
      }
    } else {
      adminEventLogger.Log(String.format("user-storage/%s/sync-error", model.getName()),
          "See server log for more details!");

      try {
        String body = String.format(
            "Error during user synchronization for federation provider '%s' in realm: '%s'. Errors:<br/><br/>%s",
            model.getName(), realm.getName(), String.join("<br/><br/>", errors));

        emailSenderProvider.send(realm.getSmtpConfig(), "log.rmgroup@f24.com", "Error in user sync", body, body);
      } catch (EmailException ex) {
        logger.errorf(ex, "Failed to send email");
      }
    }

    return synchronizationResult;
  }

  class GroupMapConfig {
    private Map<String, GroupModel> groupMap = new HashMap<>();

    private List<String> errors = new ArrayList<>();

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
      session.getContext().setRealm(realm);
      groupMapConfig.setProperties(GetGroupMapConfig(session, realm, config));
    });
    return groupMapConfig;
  }

  private GroupMapConfig GetGroupMapConfig(KeycloakSession session, RealmModel realm, ComponentModel config) {
    GroupMapConfig groupMapConfig = new GroupMapConfig();
    Map<String, GroupModel> groupMap = groupMapConfig.groupMap;
    List<String> errors = groupMapConfig.errors;

    if (config.contains(CONFIG_KEY_GROUP_MAP)) {
      String json = config.get(CONFIG_KEY_GROUP_MAP);

      try {
        Map<String, Object> jsonMap = new JSONObject(json).toMap();
        jsonMap.forEach((k, v) -> {
          try {
            GroupModel kcGroup = KeycloakModelUtils.findGroupByPath(session, realm, v.toString());
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
      } catch (JSONException e) {
        String errorMessage = String.format("Error in group map JSON '%s'. '%s'", json, e.getMessage());
        logger.error(errorMessage, e);
        errors.add(errorMessage);
      }
    }

    return groupMapConfig;
  }

  private ItcnApiUserResult importApiUsers(KeycloakSessionFactory sessionFactory, final String realmId,
      final ComponentModel fedModel, List<ItcnApiUser> apiUsers, List<String> allowUpdateUpnDomains,
      Map<String, GroupModel> groupMap) {
    final String fedId = fedModel.getId();

    final Set<String> apiUsersUpnSet = apiUsers.stream().map(u -> u.getUpn()).distinct()
        .collect(Collectors.toSet());

    final List<String> errors = new ArrayList<>();

    final AtomicInteger removedCount = new AtomicInteger(0);
    final AtomicInteger addedCount = new AtomicInteger(0);
    final AtomicInteger updatedCount = new AtomicInteger(0);
    final AtomicInteger failedCount = new AtomicInteger(0);

    final int totalExistingUsers = KeycloakModelUtils.runJobInTransactionWithResult(sessionFactory,
        (KeycloakSession session) -> {
          try {
            RealmModel realm = session.realms().getRealm(realmId);
            session.getContext().setRealm(realm);
            UserProvider userProvider = session.users();
            return userProvider.getUsersCount(realm);
          } catch (Exception e) {
            logger.errorf(e,
                "Error getting user count in federation provider '%s'. Will not be able to remove non existing users!",
                fedModel.getName());
            errors.add(String.format(
                "Error getting user count in federation provider '%s'. Will not be able to remove non existing users! Exception:<br/>%s",
                fedModel.getName(), getErrorMessage(e)));
            return -1;
          }
        });

    Boolean onlyUseGroupsInGroupMap = fedModel.get(CONFIG_KEY_ONLY_USE_GROUPS_IN_GROUP_MAP, false);

    if (totalExistingUsers > 0) {
      int totalPagesExistingUsers = (int) Math.ceil((double) totalExistingUsers / USER_REMOVE_PAGE_SIZE);

      CopyOnWriteArrayList<UserModel> usersToRemove = new CopyOnWriteArrayList<>();

      IntStream.range(0, totalPagesExistingUsers).parallel().forEach(page -> {
        KeycloakModelUtils.runJobInTransaction(sessionFactory, (KeycloakSession session) -> {
          RealmModel realm = session.realms().getRealm(realmId);
          session.getContext().setRealm(realm);
          UserProvider userProvider = session.users();
          int firstResult = page * USER_REMOVE_PAGE_SIZE;
          int maxResults = USER_REMOVE_PAGE_SIZE;

          try {
            usersToRemove.addAll(userProvider
                .searchForUserStream(realm, new HashMap<>(), firstResult, maxResults)
                .filter(u -> fedId.equals(u.getFederationLink()) && !apiUsersUpnSet.contains(u.getUsername()))
                .collect(Collectors.toList()));
          } catch (Exception e) {
            logger.errorf(e,
                "Error getting users to remove in federation provider '%s'. Might not be able to remove all non existing users!",
                fedModel.getName());
            errors.add(String.format(
                "Error getting users to remove in federation provider '%s'. Might not be able to remove all non existing users! Exception:<br/>%s",
                fedModel.getName(), getErrorMessage(e)));
          }
        });
      });

      int totalUsersToRemove = usersToRemove.size();

      if (totalUsersToRemove > 0) {
        int totalPagesUsersToRemove = (int) Math.ceil((double) totalUsersToRemove / USER_REMOVE_PAGE_SIZE);
        IntStream.range(0, totalPagesUsersToRemove).parallel().forEach(page -> {

          KeycloakModelUtils.runJobInTransaction(sessionFactory, (KeycloakSession session) -> {
            RealmModel realm = session.realms().getRealm(realmId);
            session.getContext().setRealm(realm);
            UserProvider userProvider = session.users();

            int startIndex = page * USER_REMOVE_PAGE_SIZE;
            int endIndex = Math.min(startIndex + USER_REMOVE_PAGE_SIZE, totalUsersToRemove);

            List<UserModel> usersToRemovePage = usersToRemove.subList(startIndex, endIndex);

            for (final UserModel user : usersToRemovePage) {
              try {
                userProvider.removeUser(realm, user);
                removedCount.incrementAndGet();
              } catch (Exception e) {
                logger.errorf(e,
                    "Error removing non existing user with username '%s' in federation provider '%s'",
                    user.getUsername(), fedModel.getName());
                errors.add(String.format(
                    "Error removing non existing user with username '%s' in federation provider '%s'. Exception:<br/>%s",
                    user.getUsername(), fedModel.getName(), getErrorMessage(e)));
                failedCount.incrementAndGet();
              }
            }
          });
        });
      }
    }

    int totalApiUsers = apiUsers.size();

    if (totalApiUsers > 0) {
      int totalPagesApiUsers = (int) Math.ceil((double) totalApiUsers / USER_IMPORT_PAGE_SIZE);
      IntStream.range(0, totalPagesApiUsers).parallel().forEach(page -> {
        KeycloakModelUtils.runJobInTransaction(sessionFactory, (KeycloakSession session) -> {
          RealmModel realm = session.realms().getRealm(realmId);
          session.getContext().setRealm(realm);
          UserProvider userProvider = session.users();

          int startIndex = page * USER_IMPORT_PAGE_SIZE;
          int endIndex = Math.min(startIndex + USER_IMPORT_PAGE_SIZE, totalApiUsers);

          List<ItcnApiUser> apiUsersPage = apiUsers.subList(startIndex, endIndex);

          apiUsersPage.forEach(apiUser -> {
            try {
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
                    errors.add(String.format(
                        "User with UPN '%s' is not updated during sync as he already exists in Keycloak database but is not linked to federation provider '%s' and UPN domain does not match any of '%s'",
                        apiUser.getUpn(), fedModel.getName(), String.join(", ", allowUpdateUpnDomains)));
                    failedCount.incrementAndGet();
                    return;
                  }
                  importedUser = existingLocalUser;
                } else {
                  logger.warnf(
                      "User with UPN '%s' is not updated during sync as he already exists in Keycloak database but is not linked to federation provider '%s'",
                      apiUser.getUpn(), fedModel.getName());
                  errors.add(String.format(
                      "User with UPN '%s' is not updated during sync as he already exists in Keycloak database but is not linked to federation provider '%s'",
                      apiUser.getUpn(), fedModel.getName()));
                  failedCount.incrementAndGet();
                  return;
                }
              }

              boolean attributesChanged = !apiUserEqualsLocalUser(apiUser, existingLocalUser);

              if (attributesChanged) {
                importedUser.setFederationLink(fedId);
                importedUser.setEmail(apiUser.getEmail());
                importedUser.setEmailVerified(true);
                importedUser.setFirstName(apiUser.getFirstName());
                importedUser.setLastName(apiUser.getSurName());
                importedUser.setSingleAttribute("mobile", apiUser.getMobilePhone());
                importedUser.setEnabled(true);
              }

              boolean groupsChanged = false;

              String[] apiUserGroups = apiUser.getGroups();

              HashSet<String> groupIds = new HashSet<>();

              if (groupMap != null && !groupMap.isEmpty() && apiUserGroups != null && apiUserGroups.length > 0) {
                for (String apiUserGroup : apiUserGroups) {
                  if (groupMap.containsKey(apiUserGroup)) {
                    GroupModel kcGroup = groupMap.get(apiUserGroup);
                    groupIds.add(kcGroup.getId());
                    if (!importedUser.isMemberOf(kcGroup)) {
                      groupsChanged = true;
                      importedUser.joinGroup(kcGroup);
                    }
                  }
                }

                HashSet<String> groupMapGroupIds = new HashSet<>();

                for (GroupModel group : groupMap.values()) {
                  groupMapGroupIds.add(group.getId());
                }

                List<GroupModel> groupsToLeave = importedUser.getGroupsStream().filter(g -> {
                  if (onlyUseGroupsInGroupMap) {
                    return groupMapGroupIds.contains(g.getId()) && !groupIds.contains(g.getId());
                  } else {
                    return !groupIds.contains(g.getId());
                  }
                }).collect(Collectors.toList());

                if (!groupsToLeave.isEmpty()) {
                  groupsChanged = true;
                  groupsToLeave.forEach(g -> {
                    importedUser.leaveGroup(g);
                  });
                }
              }

              if (existingLocalUser == null) {
                addedCount.incrementAndGet();
              } else if (attributesChanged || groupsChanged) {
                updatedCount.incrementAndGet();
              }
            } catch (Exception e) {
              logger.errorf(e,
                  "Error importing user from api with username '%s' in federation provider '%s'",
                  apiUser.getUpn(), fedModel.getName());
              errors.add(String.format(
                  "Error importing user from api with username '%s' in federation provider '%s'. Exception:<br/>%s",
                  apiUser.getUpn(), fedModel.getName(), getErrorMessage(e)));
              failedCount.incrementAndGet();
            }
          });
        });
      });
    }

    final ItcnSynchronizationResult syncResult = new ItcnSynchronizationResult();

    syncResult.setFailed(failedCount.get());
    syncResult.setAdded(addedCount.get());
    syncResult.setUpdated(updatedCount.get());
    syncResult.setRemoved(removedCount.get());
    syncResult.setFetched(totalApiUsers);

    return new ItcnApiUserResult(syncResult, errors);
  }

  private static boolean apiUserEqualsLocalUser(ItcnApiUser apiUser, UserModel existingLocalUser) {
    return existingLocalUser != null &&
        Objects.equals(apiUser.getUpn(), existingLocalUser.getUsername()) &&
        Objects.equals(apiUser.getEmail(), existingLocalUser.getEmail()) &&
        Objects.equals(apiUser.getFirstName(), existingLocalUser.getFirstName()) &&
        Objects.equals(apiUser.getSurName(), existingLocalUser.getLastName()) &&
        Objects.equals(apiUser.getMobilePhone(), existingLocalUser.getFirstAttribute("mobile"));
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

  private static List<ItcnApiUser> getItcnApiUsers(String usersUrl, String token) throws Exception {
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

  private String getErrorMessage(Throwable e) {
    String errorMessage = e.getMessage();
    Throwable cause = e.getCause();

    if (cause != null) {
      errorMessage += "<br/>Caused by: " + getErrorMessage(cause);
    }

    return errorMessage;
  }
}
