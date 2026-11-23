package com.netflix.spinnaker.echo.pipelinetriggers.postprocessors;

public interface PipelinePostProcessor {
  Object processPipeline(Pipeline inputPipeline);
}
