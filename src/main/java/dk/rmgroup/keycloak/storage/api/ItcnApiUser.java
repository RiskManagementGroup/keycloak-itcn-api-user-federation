package dk.rmgroup.keycloak.storage.api;

public class ItcnApiUser {
  private final String upn;
  private final String email;
  private final String firstName;
  private final String surName;
  private final String mobilePhone;

  public ItcnApiUser(String upn, String email, String firstName, String surName, String mobilePhone) {
    this.upn = upn;
    this.email = email;
    this.firstName = firstName;
    this.surName = surName;
    this.mobilePhone = mobilePhone;
  }

  public String getUpn() {
    return upn;
  }

  public String getEmail() {
    return email;
  }

  public String getFirstName() {
    return firstName;
  }

  public String getSurName() {
    return surName;
  }

  public String getMobilePhone() {
    return mobilePhone;
  }
}
