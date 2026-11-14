package com.netflix.spinnaker.echo.pipelinetriggers.postprocessors;

import java.util.Collections;
import java.util.List;
import java.util.Map;
import org.springframework.expression.EvaluationContext;
import org.springframework.expression.ExpressionParser;
import org.springframework.expression.ParserContext;
import org.springframework.expression.common.TemplateParserContext;
import org.springframework.expression.spel.standard.SpelExpressionParser;
import org.springframework.expression.spel.support.StandardEvaluationContext;

/**
 * CVE-2026-32613 mini: tainted pipeline object (user-controlled expected artifacts
 * carrying ${SpEL} expressions) is bound as root of an unrestricted
 * StandardEvaluationContext and later evaluated by the expression transform.
 */
public class ExpectedArtifactExpressionEvaluationPostProcessor implements PipelinePostProcessor {
  private final ExpressionParser parser;
  private final ParserContext parserContext = new TemplateParserContext("${", "}");

  public ExpectedArtifactExpressionEvaluationPostProcessor() {
    parser = new SpelExpressionParser();
  }

  @Override
  public Pipeline processPipeline(Pipeline inputPipeline) {
    EvaluationContext evaluationContext = new StandardEvaluationContext(inputPipeline);

    List<Map<String, Object>> expectedArtifacts = inputPipeline.getExpectedArtifacts();
    if (expectedArtifacts == null) {
      expectedArtifacts = Collections.emptyList();
    }
    for (Map<String, Object> artifactMap : expectedArtifacts) {
      Map<String, Object> evaluated =
          new ExpressionTransform(parserContext, parser).transformMap(artifactMap, evaluationContext);
      inputPipeline.record(evaluated);
    }
    return inputPipeline;
  }
}
