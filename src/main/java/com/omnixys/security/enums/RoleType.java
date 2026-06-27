package com.omnixys.security.enums;

public enum RoleType {

  ADMIN("Admin"),
  SUPREME("Supreme"),
  BASIC("Basic"),
  ELITE("Elite"),
  USER("User");

  public static final String ROLE_PREFIX = "ROLE_";

  private final String displayName;

  RoleType(String displayName) {
    this.displayName = displayName;
  }

  public String getDisplayName() {
    return displayName;
  }

  public String getPrefixedRole() {
    return ROLE_PREFIX + displayName.toUpperCase();
  }
}
