package org.apache.ofbiz.widget;

import java.io.StringWriter;
import java.util.HashMap;
import java.util.Map;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.apache.ofbiz.base.util.UtilHttp;
import org.apache.ofbiz.common.email.EmailServices;
import org.apache.ofbiz.content.data.DataResourceWorker;
import org.apache.ofbiz.entity.Delegator;
import org.apache.ofbiz.service.DispatchContext;
import org.apache.ofbiz.service.LocalDispatcher;
import org.apache.ofbiz.widget.model.ModelFormField;
import org.apache.ofbiz.widget.model.ModelFormFieldBuilder;
import org.apache.ofbiz.widget.model.ModelScreenWidget.ScreenLink;
import org.apache.ofbiz.widget.renderer.macro.MacroScreenRenderer;

/**
 * Mini reproduction entry (synthetic) for the Apache OFBiz 24.09 SSTI family
 * (CVE-2026-82910 / CVE-2026-82912 / CVE-2026-82960).
 *
 * It mirrors the wiring the widget framework performs at runtime: HTTP
 * request parameters land in the screen context Map (UtilHttp.getParameterMap
 * -> context.put("parameters", ...)), and the vulnerable renderer/service
 * methods consume that context.
 */
public class OfbizSstiEntry {

    // CVE-2026-82910: ScreenLink parameter values are expanded from the
    // tainted context and appended unescaped into the FTL macro string that
    // executeMacro evaluates (MacroScreenRenderer.renderLink).
    public void miniRenderLinkEntry(HttpServletRequest request, HttpServletResponse response) throws Exception {
        Map<String, Object> context = new HashMap<>();
        Map<String, Object> parameters = UtilHttp.getParameterMap(request);
        context.put("parameters", parameters);
        MacroScreenRenderer renderer = new MacroScreenRenderer(null, null);
        ScreenLink link = null;
        StringWriter writer = new StringWriter();
        renderer.renderLink(writer, context, link);
    }

    // CVE-2026-82960: the form-field use-when expression is built by
    // expanding ${} placeholders from the tainted context and is then
    // evaluated as a Groovy expression (ModelFormField.shouldUse ->
    // GroovyUtil.eval).
    public void miniFormUseWhenEntry(HttpServletRequest request) {
        Map<String, Object> context = new HashMap<>();
        context.put("parameters", UtilHttp.getParameterMap(request));
        ModelFormField field = ModelFormField.from(new ModelFormFieldBuilder());
        field.shouldUse(context);
    }

    // CVE-2026-82912: sendMailFromScreen expands the bodyText/subject service
    // input attributes as FTL templates (FlexibleStringExpander.expandString
    // with the template string itself in arg0).
    public void miniEmailBodyEntry(HttpServletRequest request) {
        Map<String, Object> serviceContext = new HashMap<>();
        serviceContext.put("bodyText", request.getParameter("bodyText"));
        serviceContext.put("subject", request.getParameter("subject"));
        DispatchContext dctx = null;
        EmailServices.sendMailFromScreen(dctx, serviceContext);
    }

    // CVE-2026-85627: a DataResource row (attacker-writable via
    // updateLayoutImage second-order store) is read back and its text is
    // evaluated as an FTL template (DataResourceWorker.renderDataResource
    // AsText -> getDataResourceText -> FreeMarkerWorker.renderTemplateFromString).
    public void miniDataResourceEntry() throws Exception {
        LocalDispatcher dispatcher = null;
        Delegator delegator = null;
        Map<String, Object> templateContext = new HashMap<>();
        StringWriter out = new StringWriter();
        DataResourceWorker.renderDataResourceAsText(dispatcher, delegator, "layoutImage",
                templateContext, out, false);
    }
}
