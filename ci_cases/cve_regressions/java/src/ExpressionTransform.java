package com.netflix.spinnaker.echo.pipelinetriggers.postprocessors;

import java.util.Map;
import org.springframework.expression.EvaluationContext;
import org.springframework.expression.ExpressionParser;
import org.springframework.expression.ParserContext;

/** Stand-in for kork ExpressionTransform: evaluates ${...} templates against the context. */
public class ExpressionTransform {
  private final ParserContext parserContext;
  private final ExpressionParser parser;

  public ExpressionTransform(ParserContext parserContext, ExpressionParser parser) {
    this.parserContext = parserContext;
    this.parser = parser;
  }

  public Map<String, Object> transformMap(Map<String, Object> artifactMap, EvaluationContext evaluationContext) {
    for (Map.Entry<String, Object> e : artifactMap.entrySet()) {
      if (e.getValue() instanceof String) {
        parser.parseExpression((String) e.getValue()).getValue(evaluationContext);
      }
    }
    return artifactMap;
  }
}
