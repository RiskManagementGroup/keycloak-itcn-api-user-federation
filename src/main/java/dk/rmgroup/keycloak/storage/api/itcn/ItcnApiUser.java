package dk.rmgroup.keycloak.storage.api.itcn;

import java.util.Optional;

public class ItcnApiUser {
  private final String upn;
  private final String email;
  private final String firstName;
  private final String surName;
  private final String mobilePhone;
  private final String[] groups;

  public ItcnApiUser(String upn, String email, String firstName, String surName, String mobilePhone, String[] groups) {
    this.upn = Optional.ofNullable(upn).map(String::toLowerCase).orElse(upn);
    this.email = Optional.ofNullable(email).map(String::toLowerCase).orElse(email);
    this.firstName = firstName;
    this.surName = surName;
    this.mobilePhone = mobilePhone;
    this.groups = groups;
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

  public String[] getGroups() {
    return groups;
  }
}
