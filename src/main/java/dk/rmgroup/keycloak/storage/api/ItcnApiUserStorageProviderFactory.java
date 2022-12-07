package dk.rmgroup.keycloak.storage.api;

import static dk.rmgroup.keycloak.storage.api.ItcnApiUserStorageProviderConstants.CONFIG_KEY_ACTIVE_DIRECTORY_URL;
import static dk.rmgroup.keycloak.storage.api.ItcnApiUserStorageProviderConstants.CONFIG_KEY_LOGIN_URL;
import static dk.rmgroup.keycloak.storage.api.ItcnApiUserStorageProviderConstants.CONFIG_KEY_PASSWORD;
import static dk.rmgroup.keycloak.storage.api.ItcnApiUserStorageProviderConstants.CONFIG_KEY_USERNAME;

import java.io.BufferedReader;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.net.HttpURLConnection;
import java.net.URL;
import java.net.URLConnection;
import java.nio.charset.StandardCharsets;
import java.util.Date;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;
import java.util.stream.IntStream;

import org.jboss.logging.Logger;
import org.json.JSONArray;
import org.json.JSONObject;
import org.keycloak.component.ComponentModel;
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
        .helpText("Username used for authentication")
        .add()
        .property()
        .name(CONFIG_KEY_PASSWORD)
        .label("Password")
        .type(ProviderConfigProperty.STRING_TYPE)
        .helpText("Password used for authentication")
        .add()
        .property()
        .name(CONFIG_KEY_ACTIVE_DIRECTORY_URL)
        .label("ActiveDirectory endpoint URL")
        .type(ProviderConfigProperty.STRING_TYPE)
        .helpText("URL to the ActiveDirectory endpoint")
        .add()
        .build();
  }

  @Override
  public String getId() {
    return "itcn-api-user-provider";
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

  private SynchronizationResult syncImpl(KeycloakSessionFactory sessionFactory, String realmId,
      UserStorageProviderModel model) {
    String token;
    try {
      token = getToken(model.get(CONFIG_KEY_LOGIN_URL), model.get(CONFIG_KEY_USERNAME), model.get(CONFIG_KEY_PASSWORD));
    } catch (Exception e) {
      logger.errorf(e, "Error getting token for federation provider '%s'. Please check Login endpoint URL and username and password!", model.getName());
      SynchronizationResult synchronizationResult = new SynchronizationResult();
      synchronizationResult.setFailed(1);
      return synchronizationResult;
    }
    List<ItcnApiUser> apiUsers;
    try {
      apiUsers = getUsers(model.get(CONFIG_KEY_ACTIVE_DIRECTORY_URL), token);
    } catch (Exception e) {
      logger.errorf(e, "Error getting users for federation provider '%s'. Please check ActiveDirectory endpoint url!", model.getName());
      SynchronizationResult synchronizationResult = new SynchronizationResult();
      synchronizationResult.setFailed(1);
      return synchronizationResult;
    }

    return importApiUsers(sessionFactory, realmId, model, apiUsers);
  }

  private SynchronizationResult importApiUsers(KeycloakSessionFactory sessionFactory, final String realmId,
      final ComponentModel fedModel, List<ItcnApiUser> apiUsers) {
    final SynchronizationResult syncResult = new SynchronizationResult();

    final String fedId = fedModel.getId();

    final Map<String, String> apiUsersUpnMap = apiUsers.stream().map(u -> u.getUpn()).distinct()
        .collect(Collectors.toMap(u -> u, u -> u));

    KeycloakModelUtils.runJobInTransaction(sessionFactory, new KeycloakSessionTask() {

      @Override
      public void run(KeycloakSession session) {
        try {
          RealmModel realm = session.realms().getRealm(realmId);
          UserProvider userProvider = session.users();
          List<UserModel> usersToRemove = userProvider.getUsersStream(realm)
              .filter(u -> fedId.equals(u.getFederationLink()) && !apiUsersUpnMap.containsKey(u.getUsername()))
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
              if (!fedId.equals(existingLocalUser.getFederationLink())) {
                logger.warnf(
                    "User with UPN '%s' is not updated during sync as he already exists in Keycloak database but is not linked to federation provider '%s'",
                    apiUser.getUpn(), fedModel.getName());
                return;
              }
              importedUser = existingLocalUser;
            }
            importedUser.setFederationLink(fedId);
            importedUser.setEmail(apiUser.getEmail());
            importedUser.setEmailVerified(true);
            importedUser.setFirstName(apiUser.getFirstName());
            importedUser.setLastName(apiUser.getSurName());
            importedUser.setSingleAttribute("mobile", apiUser.getMobilePhone());
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
        return new ItcnApiUser(o.getString("UPN"), o.getString("Email"), o.getString("FirstName"), o.getString("SurName"), o.getString("MobilePhone"));
      }).collect(Collectors.toList());
      return users;
    }
  }
}
