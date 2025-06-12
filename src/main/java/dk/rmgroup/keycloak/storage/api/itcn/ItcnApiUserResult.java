package dk.rmgroup.keycloak.storage.api.itcn;

import java.util.List;

import org.keycloak.storage.user.SynchronizationResult;

public class ItcnApiUserResult {
  public SynchronizationResult synchronizationResult;
  public List<String> errors;

  public ItcnApiUserResult(SynchronizationResult synchronizationResult, List<String> errors) {
    this.synchronizationResult = synchronizationResult;
    this.errors = errors;
  }
}
