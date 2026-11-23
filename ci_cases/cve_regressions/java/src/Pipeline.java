package com.netflix.spinnaker.echo.pipelinetriggers.postprocessors;

import java.util.List;
import java.util.Map;

public class Pipeline {
  private List<Map<String, Object>> expectedArtifacts;

  public List<Map<String, Object>> getExpectedArtifacts() {
    return expectedArtifacts;
  }

  public void record(Map<String, Object> evaluated) {}
}
