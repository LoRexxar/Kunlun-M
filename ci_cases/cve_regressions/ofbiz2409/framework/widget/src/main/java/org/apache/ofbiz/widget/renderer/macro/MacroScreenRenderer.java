/*******************************************************************************
 * Licensed to the Apache Software Foundation (ASF) under one
 * or more contributor license agreements.  See the NOTICE file
 * distributed with this work for additional information
 * regarding copyright ownership.  The ASF licenses this file
 * to you under the Apache License, Version 2.0 (the
 * "License"); you may not use this file except in compliance
 * with the License.  You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 *******************************************************************************/
package org.apache.ofbiz.widget.renderer.macro;

import java.io.IOException;
import java.io.Reader;
import java.io.StringReader;
import java.io.StringWriter;
import java.math.BigDecimal;
import java.net.URI;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Locale;
import java.util.Map;
import java.util.WeakHashMap;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.xml.parsers.ParserConfigurationException;

import org.apache.ofbiz.base.util.Debug;
import org.apache.ofbiz.base.util.GeneralException;
import org.apache.ofbiz.base.util.UtilFormatOut;
import org.apache.ofbiz.base.util.UtilGenerics;
import org.apache.ofbiz.base.util.UtilHttp;
import org.apache.ofbiz.base.util.UtilMisc;
import org.apache.ofbiz.base.util.UtilProperties;
import org.apache.ofbiz.base.util.UtilValidate;
import org.apache.ofbiz.base.util.template.FreeMarkerWorker;
import org.apache.ofbiz.entity.Delegator;
import org.apache.ofbiz.entity.GenericValue;
import org.apache.ofbiz.service.LocalDispatcher;
import org.apache.ofbiz.webapp.control.RequestHandler;
import org.apache.ofbiz.webapp.taglib.ContentUrlTag;
import org.apache.ofbiz.widget.WidgetWorker;
import org.apache.ofbiz.widget.content.WidgetContentWorker;
import org.apache.ofbiz.widget.content.WidgetDataResourceWorker;
import org.apache.ofbiz.widget.model.ModelForm;
import org.apache.ofbiz.widget.model.ModelScreen;
import org.apache.ofbiz.widget.model.ModelScreenWidget;
import org.apache.ofbiz.widget.model.ModelScreenWidget.Column;
import org.apache.ofbiz.widget.model.ModelScreenWidget.ColumnContainer;
import org.apache.ofbiz.widget.model.ModelTheme;
import org.apache.ofbiz.widget.model.ModelWidget;
import org.apache.ofbiz.widget.model.ScreenFactory;
import org.apache.ofbiz.widget.renderer.FormStringRenderer;
import org.apache.ofbiz.widget.renderer.MenuStringRenderer;
import org.apache.ofbiz.widget.renderer.Paginator;
import org.apache.ofbiz.widget.renderer.ScreenRenderer;
import org.apache.ofbiz.widget.renderer.ScreenStringRenderer;
import org.apache.ofbiz.widget.renderer.VisualTheme;
import org.apache.ofbiz.widget.renderer.html.HtmlWidgetRenderer;
import org.xml.sax.SAXException;

import freemarker.core.Environment;
import freemarker.template.Template;
import freemarker.template.TemplateException;

public class MacroScreenRenderer implements ScreenStringRenderer {

    private static final String MODULE = MacroScreenRenderer.class.getName();
    private Template macroLibrary;
    private WeakHashMap<Appendable, Environment> environments = new WeakHashMap<>();
    private String rendererName;
    private int elementId = 999;
    private boolean widgetCommentsEnabled = false;
    private int screenLetsIdCounter = 1;

    public MacroScreenRenderer(ModelTheme theme, String modelTemplateName) throws TemplateException, IOException {
        this(theme.getType(modelTemplateName), theme.getScreenRendererLocation(modelTemplateName));
    }

    public MacroScreenRenderer(String name, String macroLibraryPath) throws TemplateException, IOException {
        macroLibrary = FreeMarkerWorker.getTemplate(macroLibraryPath);
        rendererName = name;
    }

    @Deprecated
    public MacroScreenRenderer(String name, String macroLibraryPath, Appendable writer) throws TemplateException, IOException {
        this(name, macroLibraryPath);
    }

    private String getNextElementId() {
        elementId++;
        return "hsr" + elementId;
    }

    private void executeMacro(Appendable writer, String macro) throws IOException {
        try {
            Environment environment = getEnvironment(writer);
            Reader templateReader = new StringReader(macro);
            // FIXME: I am using a Date as an hack to provide a unique name for the template...
            Template template = new Template((new java.util.Date()).toString(), templateReader, FreeMarkerWorker.getDefaultOfbizConfig());
            templateReader.close();
            environment.include(template);
        } catch (TemplateException | IOException e) {
            Debug.logError(e, "Error rendering screen macro [" + macro + "] thru ftl", MODULE);
        }
    }

    private void executeMacro(Appendable writer, String macroName, Map<String, Object> parameters) throws IOException {
        StringBuilder sb = new StringBuilder("<@");
        sb.append(macroName);
        if (parameters != null) {
            for (Map.Entry<String, Object> parameter : parameters.entrySet()) {
                sb.append(' ');
                sb.append(parameter.getKey());
                sb.append("=");
                Object value = parameter.getValue();
                if (value instanceof String) {
                    sb.append('"');
                    sb.append(((String) value).replace("\\", "\\\\").replace("\"", "\\\"").replace("$", "\\$"));
                    sb.append('"');
                } else {
                    sb.append(value);
                }
            }
        }
        sb.append(" />");
        executeMacro(writer, sb.toString());
    }

    private Environment getEnvironment(Appendable writer) throws TemplateException, IOException {
        Environment environment = environments.get(writer);
        if (environment == null) {
            Map<String, Object> input = UtilMisc.toMap("key", null);
            environment = FreeMarkerWorker.renderTemplate(macroLibrary, input, writer);
            environments.put(writer, environment);
        }
        return environment;
    }

    @Override
    public String getRendererName() {
        return rendererName;
    }

    @Override
    public void renderBegin(Appendable writer, Map<String, Object> context) throws IOException {
        executeMacro(writer, "renderBegin", null);
    }

    @Override
    public void renderEnd(Appendable writer, Map<String, Object> context) throws IOException {
        executeMacro(writer, "renderEnd", null);
    }

    @Override
    public void renderScreenBegin(Appendable writer, Map<String, Object> context, ModelScreen modelScreen) throws IOException {
        ScreenRenderer.ScreenStack screenStack = WidgetWorker.getScreenStack(context);
        screenStack.push(modelScreen);
        executeMacro(writer, "renderScreenBegin", null);
    }

    @Override
    public void renderScreenEnd(Appendable writer, Map<String, Object> context, ModelScreen modelScreen) throws IOException {
        ScreenRenderer.ScreenStack screenStack = WidgetWorker.getScreenStack(context);
        screenStack.drop();
        executeMacro(writer, "renderScreenEnd", null);
    }

    @Override
    public void renderSectionBegin(Appendable writer, Map<String, Object> context, ModelScreenWidget.Section section) throws IOException {
        if (section.isMainSection()) {
            this.widgetCommentsEnabled = ModelWidget.widgetBoundaryCommentsEnabled(context);
        }
        if (this.widgetCommentsEnabled) {
            StringBuilder sb = new StringBuilder("Begin section widget")
                    .append(section.getBoundaryCommentName());
            if (section.isMainSection()) {
                ScreenRenderer.ScreenStack screenStack = WidgetWorker.getScreenStack(context);
                sb.append(" id ")
                        .append(screenStack.resolveCurrentScreenId());
            }
            executeMacro(writer, "renderSectionBegin", UtilMisc.toMap("boundaryComment", sb.toString()));
        }
        if (HtmlWidgetRenderer.NAMED_BORDER_TYPE != ModelWidget.NamedBorderType.NONE && section.isMainSection()) {
            // render start of named border for screen
            writer.append(HtmlWidgetRenderer.beginNamedBorder("Screen",
                    section.getBoundaryCommentName(), ((HttpServletRequest) context.get("request")).getContextPath()));
        }
    }
    @Override
    public void renderSectionEnd(Appendable writer, Map<String, Object> context, ModelScreenWidget.Section section) throws IOException {
        if (HtmlWidgetRenderer.NAMED_BORDER_TYPE != ModelWidget.NamedBorderType.NONE && section.isMainSection()) {
            // render end of named border for screen
            writer.append(HtmlWidgetRenderer.endNamedBorder("Screen", section.getBoundaryCommentName()));
        }
        if (this.widgetCommentsEnabled) {
            StringBuilder sb = new StringBuilder("End section Widget ")
                    .append(section.getBoundaryCommentName());
            if (section.isMainSection()) {
                ScreenRenderer.ScreenStack screenStack = WidgetWorker.getScreenStack(context);
                sb.append(" id ")
                        .append(screenStack.resolveCurrentScreenId());
            }
            executeMacro(writer, "renderSectionEnd", UtilMisc.toMap("boundaryComment", sb.toString()));
        }
    }

    @Override
    public void renderContainerBegin(Appendable writer, Map<String, Object> context, ModelScreenWidget.Container container) throws IOException {
        String containerId = container.getId(context);
        String containerType = container.getType(context);
        String autoUpdateTarget = container.getAutoUpdateTargetExdr(context);
        HttpServletRequest request = (HttpServletRequest) context.get("request");
        String autoUpdateLink = "";
        if (UtilValidate.isNotEmpty(autoUpdateTarget) && UtilHttp.isJavaScriptEnabled(request)) {
            if (UtilValidate.isEmpty(containerId)) {
                containerId = getNextElementId();
            }
            HttpServletResponse response = (HttpServletResponse) context.get("response");
            RequestHandler rh = RequestHandler.from(request);
            autoUpdateLink = rh.makeLink(request, response, autoUpdateTarget);
        }
        Map<String, Object> parameters = new HashMap<>();
        parameters.put("id", containerId);
        parameters.put("type", containerType);
        parameters.put("style", container.getStyle(context));
        parameters.put("autoUpdateLink", autoUpdateLink);
        parameters.put("autoUpdateInterval", container.getAutoUpdateInterval(context));
        executeMacro(writer, "renderContainerBegin", parameters);
    }

    @Override
    public void renderContainerEnd(Appendable writer, Map<String, Object> context, ModelScreenWidget.Container container) throws IOException {
        String containerType = container.getType(context);
        executeMacro(writer, "renderContainerEnd", UtilMisc.toMap("type", containerType));
    }

    @Override
    public void renderLabel(Appendable writer, Map<String, Object> context, ModelScreenWidget.Label label) throws IOException {
        Map<String, Object> parameters = new HashMap<>();
        parameters.put("text", label.getText(context));
        parameters.put("id", label.getId(context));
        parameters.put("style", label.getStyle(context));
        executeMacro(writer, "renderLabel", parameters);
    }

    @Override
    public void renderHorizontalSeparator(Appendable writer, Map<String, Object> context, ModelScreenWidget.HorizontalSeparator separator)
            throws IOException {
        Map<String, Object> parameters = new HashMap<>();
        parameters.put("id", separator.getId(context));
        parameters.put("style", separator.getStyle(context));
        executeMacro(writer, "renderHorizontalSeparator", parameters);
    }

    @Override
    public void renderLink(Appendable writer, Map<String, Object> context, ModelScreenWidget.ScreenLink link) throws IOException {
        HttpServletResponse response = (HttpServletResponse) context.get("response");
        HttpServletRequest request = (HttpServletRequest) context.get("request");
        VisualTheme visualTheme = UtilHttp.getVisualTheme(request);
        ModelTheme modelTheme = visualTheme.getModelTheme();
        String targetWindow = link.getTargetWindow(context);
        String target = link.getTarget(context);

        String uniqueItemName = link.getModelScreen().getName() + "_LF_"
                + UtilMisc.<String>addToBigDecimalInMap(context, "screenUniqueItemIndex", BigDecimal.ONE);

        String linkType = WidgetWorker.determineAutoLinkType(link.getLinkType(), target, link.getUrlMode(), request);
        String actionUrl = "";
        StringBuilder parameters = new StringBuilder();
        String width = link.getWidth();
        if (UtilValidate.isEmpty(width)) {
            width = String.valueOf(modelTheme.getLinkDefaultLayeredModalWidth());
        }
        String height = link.getHeight();
        if (UtilValidate.isEmpty(height)) {
            height = String.valueOf(modelTheme.getLinkDefaultLayeredModalHeight());
        }
        boolean isModal = "layered-modal".equals(linkType);
        if ("hidden-form".equals(linkType) || isModal) {
            final URI actionUri = WidgetWorker.buildHyperlinkUri(target, link.getUrlMode(), null,
                    link.getPrefix(context), link.getFullPath(), link.getSecure(), link.getEncode(),
                    request, response);
            actionUrl = actionUri.toString();
            parameters.append("[");
            // Callback propagation only if displaying a modal
            for (Map.Entry<String, String> parameter: link.getParameterMap(context, isModal).entrySet()) {
                if (parameters.length() > 1) {
                    parameters.append(",");
                }
                parameters.append("{'name':'");
                parameters.append(parameter.getKey());
                parameters.append("'");
                parameters.append(",'value':'");
                parameters.append(parameter.getValue());
                parameters.append("'}");
            }
            parameters.append("]");
        }
        String id = link.getId(context);
        String style = link.getStyle(context);
        String name = link.getName(context);
        String text = link.getText(context);
        String linkUrl = MacroCommonRenderer.getLinkUrl(link.getLink(), linkType, context);
        String imgStr = "";
        ModelScreenWidget.ScreenImage img = link.getImage();
        if (img != null) {
            StringWriter sw = new StringWriter();
            renderImage(sw, context, img);
            imgStr = sw.toString();
        }
        StringWriter sr = new StringWriter();
        sr.append("<@renderLink ");
        sr.append("parameterList=");
        sr.append(parameters.length() == 0 ? "\"\"" : parameters.toString());
        sr.append(" targetWindow=\"");
        sr.append(targetWindow);
        sr.append("\" target=\"");
        sr.append(target);
        sr.append("\" uniqueItemName=\"");
        sr.append(uniqueItemName);
        sr.append("\" linkType=\"");
        sr.append(linkType);
        sr.append("\" actionUrl=\"");
        sr.append(actionUrl);
        sr.append("\" id=\"");
        sr.append(id);
        sr.append("\" style=\"");
        sr.append(style);
        sr.append("\" name=\"");
        sr.append(name);
        if (UtilValidate.isNotEmpty(width)) {
            sr.append("\" width=\"");
            sr.append(width);
        }
        if (UtilValidate.isNotEmpty(height)) {
            sr.append("\" height=\"");
            sr.append(height);
        }
        sr.append("\" linkUrl=\"");
        sr.append(linkUrl);
        sr.append("\" text=\"");
        sr.append(text);
        sr.append("\" imgStr=\"");
        sr.append(imgStr.replaceAll("\"", "\\\\\""));
        sr.append("\" />");
        executeMacro(writer, sr.toString());
    }

    @Override
    public void renderImage(Appendable writer, Map<String, Object> context, ModelScreenWidget.ScreenImage image) throws IOException {
        if (image == null) {
            return;
        }
        String src = image.getSrc(context);

        String urlMode = image.getUrlMode();
        boolean fullPath = false;
        boolean secure = false;
        boolean encode = false;
        HttpServletResponse response = (HttpServletResponse) context.get("response");
        HttpServletRequest request = (HttpServletRequest) context.get("request");
        String urlString = "";
        if (urlMode != null && "intra-app".equalsIgnoreCase(urlMode)) {
            if (request != null && response != null) {
                RequestHandler rh = RequestHandler.from(request);
                urlString = rh.makeLink(request, response, src, fullPath, secure, encode);
            } else {
                urlString = src;
            }
        } else if (urlMode != null && "content".equalsIgnoreCase(urlMode)) {
            if (request != null && response != null) {
                StringBuilder newURL = new StringBuilder();
                ContentUrlTag.appendContentPrefix(request, newURL);
                newURL.append(src);
                urlString = newURL.toString();
            }
        } else {
            urlString = src;
        }
        Map<String, Object> parameters = new HashMap<>();
        parameters.put("src", src);
        parameters.put("id", image.getId(context));
        parameters.put("style", image.getStyle(context));
        parameters.put("wid", image.getWidth(context));
        parameters.put("hgt", image.getHeight(context));
        parameters.put("border", image.getBorder(context));
        parameters.put("alt", image.getAlt(context));
        parameters.put("urlString", urlString);
        executeMacro(writer, "renderImage", parameters);
    }

    @Override
    public void renderContentBegin(Appendable writer, Map<String, Object> context, ModelScreenWidget.Content content) throws IOException {
        String editRequest = content.getEditRequest(context);
        String enableEditName = content.getEnableEditName(context);
        String enableEditValue = (String) context.get(enableEditName);

        if (Debug.verboseOn()) {
            Debug.logVerbose("directEditRequest:" + editRequest, MODULE);
        }

        Map<String, Object> parameters = new HashMap<>();
        parameters.put("editRequest", editRequest);
        parameters.put("enableEditValue", enableEditValue == null ? "" : enableEditValue);
        parameters.put("editContainerStyle", content.getEditContainerStyle(context));
        executeMacro(writer, "renderContentBegin", parameters);
    }

    @Override
    public void renderContentBody(Appendable writer, Map<String, Object> context, ModelScreenWidget.Content content) throws IOException {
        Locale locale = UtilMisc.ensureLocale(context.get("locale"));
        String mimeTypeId = "text/html";
        String expandedContentId = content.getContentId(context);
        String expandedDataResourceId = content.getDataResourceId(context);
        String renderedContent = null;
        LocalDispatcher dispatcher = (LocalDispatcher) context.get("dispatcher");
        Delegator delegator = (Delegator) context.get("delegator");

        // make a new map for content rendering; so our current map does not get clobbered
        Map<String, Object> contentContext = new HashMap<>();
        contentContext.putAll(context);
        String dataResourceId = (String) contentContext.get("dataResourceId");
        if (Debug.verboseOn()) {
            Debug.logVerbose("expandedContentId:" + expandedContentId, MODULE);
        }

        try {
            if (UtilValidate.isNotEmpty(dataResourceId)) {
                if (WidgetDataResourceWorker.getDataresourceWorker() != null) {
                    renderedContent = WidgetDataResourceWorker.getDataresourceWorker().renderDataResourceAsTextExt(delegator, dataResourceId,
                            contentContext, locale, mimeTypeId, false);
                } else {
                    Debug.logError("Not rendering content, WidgetDataResourceWorker.dataresourceWorker not found.", MODULE);
                }
            } else if (UtilValidate.isNotEmpty(expandedContentId)) {
                if (WidgetContentWorker.getContentWorker() != null) {
                    renderedContent = WidgetContentWorker.getContentWorker().renderContentAsTextExt(dispatcher, expandedContentId, contentContext,
                            locale, mimeTypeId, true);
                } else {
                    Debug.logError("Not rendering content, WidgetContentWorker.contentWorker not found.", MODULE);
                }
            } else if (UtilValidate.isNotEmpty(expandedDataResourceId)) {
                if (WidgetDataResourceWorker.getDataresourceWorker() != null) {
                    renderedContent = WidgetDataResourceWorker.getDataresourceWorker().renderDataResourceAsTextExt(delegator,
                            expandedDataResourceId, contentContext, locale, mimeTypeId, false);
                } else {
                    Debug.logError("Not rendering content, WidgetDataResourceWorker.dataresourceWorker not found.", MODULE);
                }
            }
            if (UtilValidate.isEmpty(renderedContent)) {
                String editRequest = content.getEditRequest(context);
                if (UtilValidate.isNotEmpty(editRequest)) {
                    if (WidgetContentWorker.getContentWorker() != null) {
                        WidgetContentWorker.getContentWorker().renderContentAsTextExt(dispatcher, "NOCONTENTFOUND", writer,
                                contentContext, locale, mimeTypeId, true);
                    } else {
                        Debug.logError("Not rendering content, WidgetContentWorker.contentWorker not found.", MODULE);
                    }
                }
            } else {
                if (content.xmlEscape()) {
                    renderedContent = UtilFormatOut.encodeXmlValue(renderedContent);
                }

                writer.append(renderedContent);
            }

        } catch (GeneralException | IOException e) {
            String errMsg = "Error rendering included content with id [" + expandedContentId + "] : " + e.toString();
            Debug.logError(e, errMsg, MODULE);
        }
    }

    @Override
    public void renderContentEnd(Appendable writer, Map<String, Object> context, ModelScreenWidget.Content content) throws IOException {
        String expandedContentId = content.getContentId(context);
        String editMode = "Edit";
        String editRequest = content.getEditRequest(context);
        String enableEditName = content.getEnableEditName(context);
        String enableEditValue = (String) context.get(enableEditName);
        String urlString = "";
        if (editRequest != null && editRequest.toUpperCase(Locale.getDefault()).indexOf("IMAGE") < 0) {
            editMode += " Image";
        }

        if (UtilValidate.isNotEmpty(editRequest) && "true".equals(enableEditValue)) {
            HttpServletResponse response = (HttpServletResponse) context.get("response");
            HttpServletRequest request = (HttpServletRequest) context.get("request");
            if (request != null && response != null) {
                if (editRequest.indexOf('?') < 0) {
                    editRequest += "?";
                } else {
                    editRequest += "&amp;";
                }
                editRequest += "contentId=" + expandedContentId;
                RequestHandler rh = RequestHandler.from(request);
                urlString = rh.makeLink(request, response, editRequest, false, false, false);
            }

            Map<String, Object> parameters = new HashMap<>();
            parameters.put("urlString", urlString);
            parameters.put("editMode", editMode);
            parameters.put("editContainerStyle", content.getEditContainerStyle(context));
            parameters.put("editRequest", editRequest);
            parameters.put("enableEditValue", enableEditValue);
            executeMacro(writer, "renderContentEnd", parameters);
        }
    }

    @Override
    public void renderContentFrame(Appendable writer, Map<String, Object> context, ModelScreenWidget.Content content) throws IOException {
        String dataResourceId = content.getDataResourceId(context);
        String urlString = "/ViewSimpleContent?dataResourceId=" + dataResourceId;
        String fullUrlString = "";
        HttpServletRequest request = (HttpServletRequest) context.get("request");
        HttpServletResponse response = (HttpServletResponse) context.get("response");
        if (request != null && response != null) {
            RequestHandler rh = RequestHandler.from(request);
            fullUrlString = rh.makeLink(request, response, urlString, true, false, false);
        }

        Map<String, Object> parameters = new HashMap<>();
        parameters.put("fullUrl", fullUrlString);
        parameters.put("width", content.getWidth());
        parameters.put("height", content.getHeight());
        parameters.put("border", content.getBorder());
        executeMacro(writer, "renderContentFrame", parameters);
    }

    @Override
    public void renderSubContentBegin(Appendable writer, Map<String, Object> context, ModelScreenWidget.SubContent content) throws IOException {
        String enableEditName = content.getEnableEditName(context);
        String enableEditValue = (String) context.get(enableEditName);

        Map<String, Object> parameters = new HashMap<>();
        parameters.put("editContainerStyle", content.getEditContainerStyle(context));
        parameters.put("editRequest", content.getEditRequest(context));
        parameters.put("enableEditValue", enableEditValue == null ? "" : enableEditValue);
        executeMacro(writer, "renderSubContentBegin", parameters);
    }

    @Override
    public void renderSubContentBody(Appendable writer, Map<String, Object> context, ModelScreenWidget.SubContent content) throws IOException {
        Locale locale = UtilMisc.ensureLocale(context.get("locale"));
        String mimeTypeId = "text/html";
        String expandedContentId = content.getContentId(context);
        String expandedMapKey = content.getMapKey(context);
        String renderedContent = "";
        LocalDispatcher dispatcher = (LocalDispatcher) context.get("dispatcher");

        // create a new map for the content rendering; so our current context does not get overwritten!
        Map<String, Object> contentContext = new HashMap<>();
        contentContext.putAll(context);

        try {
            if (WidgetContentWorker.getContentWorker() != null) {
                renderedContent = WidgetContentWorker.getContentWorker().renderSubContentAsTextExt(dispatcher, expandedContentId, expandedMapKey,
                        contentContext, locale, mimeTypeId, true);
            } else {
                Debug.logError("Not rendering content, WidgetContentWorker.contentWorker not found.", MODULE);
            }
            if (UtilValidate.isEmpty(renderedContent)) {
                String editRequest = content.getEditRequest(context);
                if (UtilValidate.isNotEmpty(editRequest)) {
                    if (WidgetContentWorker.getContentWorker() != null) {
                        WidgetContentWorker.getContentWorker().renderContentAsTextExt(dispatcher, "NOCONTENTFOUND", writer, contentContext, locale,
                                mimeTypeId, true);
                    } else {
                        Debug.logError("Not rendering content, WidgetContentWorker.contentWorker not found.", MODULE);
                    }
                }
            } else {
                if (content.xmlEscape()) {
                    renderedContent = UtilFormatOut.encodeXmlValue(renderedContent);
                }

                writer.append(renderedContent);
            }

        } catch (GeneralException | IOException e) {
            String errMsg = "Error rendering included content with id [" + expandedContentId + "] : " + e.toString();
            Debug.logError(e, errMsg, MODULE);
        }
    }

    @Override
    public void renderSubContentEnd(Appendable writer, Map<String, Object> context, ModelScreenWidget.SubContent content) throws IOException {
        String editMode = "Edit";
        String editRequest = content.getEditRequest(context);
        String enableEditName = content.getEnableEditName(context);
        String enableEditValue = (String) context.get(enableEditName);
        String expandedContentId = content.getContentId(context);
        String expandedMapKey = content.getMapKey(context);
        String urlString = "";
        if (editRequest != null && !(editRequest.toUpperCase(Locale.getDefault()).indexOf("IMAGE") < 1)) {
            editMode += " Image";
        }
        if (UtilValidate.isNotEmpty(editRequest) && "true".equals(enableEditValue)) {
            HttpServletResponse response = (HttpServletResponse) context.get("response");
            HttpServletRequest request = (HttpServletRequest) context.get("request");
            if (request != null && response != null) {
                if (editRequest.indexOf('?') < 0) {
                    editRequest += "?";
                } else {
                    editRequest += "&amp;";
                }
                editRequest += "contentId=" + expandedContentId;
                if (UtilValidate.isNotEmpty(expandedMapKey)) {
                    editRequest += "&amp;mapKey=" + expandedMapKey;
                }
                RequestHandler rh = RequestHandler.from(request);
                urlString = rh.makeLink(request, response, editRequest, false, false, false);
            }
        }

        Map<String, Object> parameters = new HashMap<>();
        parameters.put("urlString", urlString);
        parameters.put("editMode", editMode);
        parameters.put("editContainerStyle", content.getEditContainerStyle(context));
        parameters.put("editRequest", editRequest);
        parameters.put("enableEditValue", enableEditValue == null ? "" : enableEditValue);
        executeMacro(writer, "renderSubContentEnd", parameters);
    }


    @Override
    public void renderScreenletBegin(Appendable writer, Map<String, Object> context, boolean collapsed, ModelScreenWidget.Screenlet screenlet)
            throws IOException {
        HttpServletRequest request = (HttpServletRequest) context.get("request");
        HttpServletResponse response = (HttpServletResponse) context.get("response");
        VisualTheme visualTheme = UtilHttp.getVisualTheme(request);
        ModelTheme modelTheme = visualTheme.getModelTheme();
        boolean javaScriptEnabled = UtilHttp.isJavaScriptEnabled(request);
        ModelScreenWidget.Menu tabMenu = screenlet.getTabMenu();
        if (tabMenu != null) {
            tabMenu.renderWidgetString(writer, context, this);
        }

        String title = screenlet.getTitle(context);
        boolean collapsible = screenlet.collapsible();
        ModelScreenWidget.Menu navMenu = screenlet.getNavigationMenu();
        ModelScreenWidget.Form navForm = screenlet.getNavigationForm();
        String expandToolTip = "";
        String collapseToolTip = "";
        String fullUrlString = "";
        String menuString = "";
        boolean showMore = false;
        if (UtilValidate.isNotEmpty(title) || navMenu != null || navForm != null || collapsible) {
            showMore = true;
            if (collapsible) {
                this.getNextElementId();
                Map<String, Object> uiLabelMap = UtilGenerics.cast(context.get("uiLabelMap"));
                Map<String, Object> paramMap = UtilGenerics.cast(context.get("requestParameters"));
                Map<String, Object> requestParameters = new HashMap<>(paramMap);
                if (uiLabelMap != null) {
                    expandToolTip = (String) uiLabelMap.get("CommonExpand");
                    collapseToolTip = (String) uiLabelMap.get("CommonCollapse");
                }
                if (!javaScriptEnabled) {
                    requestParameters.put(screenlet.getPreferenceKey(context) + "_collapsed", collapsed ? "false" : "true");
                    String queryString = UtilHttp.urlEncodeArgs(requestParameters);
                    fullUrlString = request.getRequestURI() + "?" + queryString;
                }
            }
            StringWriter sb = new StringWriter();
            if (navMenu != null) {
                MenuStringRenderer savedRenderer = (MenuStringRenderer) context.get("menuStringRenderer");
                MenuStringRenderer renderer;
                try {
                    renderer = new MacroMenuRenderer(modelTheme.getMenuRendererLocation("screen"), request, response);
                    context.put("menuStringRenderer", renderer);
                    navMenu.renderWidgetString(sb, context, this);
                    context.put("menuStringRenderer", savedRenderer);
                } catch (TemplateException e) {
                    Debug.logError(e, MODULE);
                }
            } else if (navForm != null) {
                renderScreenletPaginateMenu(sb, context, navForm);
            }
            menuString = sb.toString();
        }

        Map<String, Object> parameters = new HashMap<>();
        parameters.put("title", title);
        parameters.put("collapsible", collapsible);
        parameters.put("saveCollapsed", screenlet.saveCollapsed());
        if (UtilValidate.isNotEmpty(screenlet.getId(context))) {
            parameters.put("id", screenlet.getId(context));
            parameters.put("collapsibleAreaId", screenlet.getId(context) + "_col");
        } else {
            parameters.put("id", "screenlet_" + screenLetsIdCounter);
            parameters.put("collapsibleAreaId", "screenlet_" + screenLetsIdCounter + "_col");
            screenLetsIdCounter++;
        }
        parameters.put("expandToolTip", expandToolTip);
        parameters.put("collapseToolTip", collapseToolTip);
        parameters.put("fullUrlString", fullUrlString);
        parameters.put("padded", screenlet.padded());
        parameters.put("menuString", menuString);
        parameters.put("showMore", showMore);
        parameters.put("collapsed", collapsed);
        parameters.put("javaScriptEnabled", javaScriptEnabled);
        executeMacro(writer, "renderScreenletBegin", parameters);
    }

    @Override
    public void renderScreenletSubWidget(Appendable writer, Map<String, Object> context, ModelScreenWidget subWidget,
                                         ModelScreenWidget.Screenlet screenlet) throws GeneralException, IOException {
        if (subWidget.equals(screenlet.getNavigationForm())) {
            HttpServletRequest request = (HttpServletRequest) context.get("request");
            HttpServletResponse response = (HttpServletResponse) context.get("response");
            if (request != null && response != null) {
                VisualTheme visualTheme = UtilHttp.getVisualTheme(request);
                ModelTheme modelTheme = visualTheme.getModelTheme();
                Map<String, Object> globalCtx = UtilGenerics.cast(context.get("globalContext"));
                globalCtx.put("NO_PAGINATOR", true);
                FormStringRenderer savedRenderer = (FormStringRenderer) context.get("formStringRenderer");
                MacroFormRenderer renderer = new MacroFormRenderer(
                        modelTheme.getFormRendererLocation("screen"), request, response);
                renderer.setRenderPagination(false);
                context.put("formStringRenderer", renderer);
                subWidget.renderWidgetString(writer, context, this);
                context.put("formStringRenderer", savedRenderer);
            }
        } else {
            subWidget.renderWidgetString(writer, context, this);
        }
    }
    @Override
    public void renderScreenletEnd(Appendable writer, Map<String, Object> context, ModelScreenWidget.Screenlet screenlet) throws IOException {
        executeMacro(writer, "renderScreenletEnd", null);
    }

    /**
     * Render screenlet paginate menu.
     * @param writer the writer
     * @param context the context
     * @param form the form
     * @throws IOException the io exception
     */
    protected void renderScreenletPaginateMenu(Appendable writer, Map<String, Object> context, ModelScreenWidget.Form form) throws IOException {
        HttpServletResponse response = (HttpServletResponse) context.get("response");
        HttpServletRequest request = (HttpServletRequest) context.get("request");
        ModelForm modelForm;
        try {
            modelForm = form.getModelForm(context);
        } catch (Exception e) {
            throw new IOException(e);
        }
        modelForm.runFormActions(context);
        Paginator.preparePager(modelForm, context);
        String targetService = modelForm.getPaginateTarget(context);
        if (targetService == null) {
            targetService = "${targetService}";
        }

        // get the parametrized pagination index and size fields
        int paginatorNumber = WidgetWorker.getPaginatorNumber(context);
        String viewIndexParam = modelForm.getMultiPaginateIndexField(context);
        String viewSizeParam = modelForm.getMultiPaginateSizeField(context);

        int viewIndex = Paginator.getViewIndex(modelForm, context);
        int viewSize = Paginator.getViewSize(modelForm, context);
        int listSize = Paginator.getListSize(context);

        int highIndex = Paginator.getHighIndex(context);
        int actualPageSize = Paginator.getActualPageSize(context);

        // if this is all there seems to be (if listSize < 0, then size is unknown)
        if (actualPageSize >= listSize && listSize >= 0) {
            return;
        }

        // needed for the "Page" and "rows" labels
        Map<String, String> uiLabelMap = UtilGenerics.cast(context.get("uiLabelMap"));
        String ofLabel = "";
        if (uiLabelMap == null) {
            Debug.logWarning("Could not find uiLabelMap in context", MODULE);
        } else {
            ofLabel = uiLabelMap.get("CommonOf");
            ofLabel = ofLabel.toLowerCase(Locale.getDefault());
        }

        // for legacy support, the viewSizeParam is VIEW_SIZE and viewIndexParam is VIEW_INDEX when the fields are "viewSize" and "viewIndex"
        if (("viewIndex" + "_" + paginatorNumber).equals(viewIndexParam)) {
            viewIndexParam = "VIEW_INDEX" + "_" + paginatorNumber;
        }
        if (("viewSize" + "_" + paginatorNumber).equals(viewSizeParam)) {
            viewSizeParam = "VIEW_SIZE" + "_" + paginatorNumber;
        }

        RequestHandler rh = RequestHandler.from(request);
        Object obj = context.get("requestParameters");

        Map<String, Object> inputFields = (obj instanceof Map) ? UtilGenerics.cast(obj) : null;
        // strip out any multi form fields if the form is of type multi
        if ("multi".equals(modelForm.getType())) {
            inputFields = UtilHttp.removeMultiFormParameters(inputFields);
        }
        String queryString = UtilHttp.urlEncodeArgs(inputFields);
        // strip legacy viewIndex/viewSize params from the query string
        queryString = UtilHttp.stripViewParamsFromQueryString(queryString, "" + paginatorNumber);
        // strip parametrized index/size params from the query string
        HashSet<String> paramNames = new HashSet<>();
        paramNames.add(viewIndexParam);
        paramNames.add(viewSizeParam);
        queryString = UtilHttp.stripNamedParamsFromQueryString(queryString, paramNames);

        String anchor = "";
        String paginateAnchor = modelForm.getPaginateTargetAnchor();
        if (paginateAnchor != null) {
            anchor = "#" + paginateAnchor;
        }

        // preparing the link text, so that later in the code we can reuse this and just add the viewIndex
        String prepLinkText = "";
        prepLinkText = targetService;
        if (prepLinkText.indexOf('?') < 0) {
            prepLinkText += "?";
        } else if (!prepLinkText.endsWith("?")) {
            prepLinkText += "&amp;";
        }
        if (UtilValidate.isNotEmpty(queryString) && !"null".equals(queryString)) {
            prepLinkText += queryString + "&amp;";
        }
        prepLinkText += viewSizeParam + "=" + viewSize + "&amp;" + viewIndexParam + "=";

        String linkText;


        // The current screenlet title bar navigation syling requires rendering
        // these links in reverse order
        // Last button
        String lastLinkUrl = "";
        if (highIndex < listSize) {
            int lastIndex = UtilMisc.getViewLastIndex(listSize, viewSize);
            linkText = prepLinkText + lastIndex + anchor;
            lastLinkUrl = rh.makeLink(request, response, linkText);
        }
        String nextLinkUrl = "";
        if (highIndex < listSize) {
            linkText = prepLinkText + (viewIndex + 1) + anchor;
            // - make the link
            nextLinkUrl = rh.makeLink(request, response, linkText);
        }
        String previousLinkUrl = "";
        if (viewIndex > 0) {
            linkText = prepLinkText + (viewIndex - 1) + anchor;
            previousLinkUrl = rh.makeLink(request, response, linkText);
        }
        String firstLinkUrl = "";
        if (viewIndex > 0) {
            linkText = prepLinkText + 0 + anchor;
            firstLinkUrl = rh.makeLink(request, response, linkText);
        }

        Map<String, Object> parameters = new HashMap<>();
        parameters.put("lowIndex", Paginator.getLowIndex(context));
        parameters.put("actualPageSize", actualPageSize);
        parameters.put("ofLabel", ofLabel);
        parameters.put("listSize", listSize);
        parameters.put("paginateLastStyle", modelForm.getPaginateLastStyle());
        parameters.put("lastLinkUrl", lastLinkUrl);
        parameters.put("paginateLastLabel", modelForm.getPaginateLastLabel(context));
        parameters.put("paginateNextStyle", modelForm.getPaginateNextStyle());
        parameters.put("nextLinkUrl", nextLinkUrl);
        parameters.put("paginateNextLabel", modelForm.getPaginateNextLabel(context));
        parameters.put("paginatePreviousStyle", modelForm.getPaginatePreviousStyle());
        parameters.put("paginatePreviousLabel", modelForm.getPaginatePreviousLabel(context));
        parameters.put("previousLinkUrl", previousLinkUrl);
        parameters.put("paginateFirstStyle", modelForm.getPaginateFirstStyle());
        parameters.put("paginateFirstLabel", modelForm.getPaginateFirstLabel(context));
        parameters.put("firstLinkUrl", firstLinkUrl);
        executeMacro(writer, "renderScreenletPaginateMenu", parameters);
    }

    @Override
    public void renderPortalPageBegin(Appendable writer, Map<String, Object> context, ModelScreenWidget.PortalPage portalPage)
            throws GeneralException, IOException {
        String portalPageId = portalPage.getActualPortalPageId(context);
        String originalPortalPageId = portalPage.getOriginalPortalPageId(context);
        String confMode = portalPage.getConfMode(context);

        Map<String, String> uiLabelMap = UtilGenerics.cast(context.get("uiLabelMap"));
        String addColumnLabel = "";
        String addColumnHint = "";
        if (uiLabelMap == null) {
            Debug.logWarning("Could not find uiLabelMap in context", MODULE);
        } else {
            addColumnLabel = uiLabelMap.get("CommonAddColumn");
            addColumnHint = uiLabelMap.get("CommonAddAColumnToThisPortalPage");
        }

        StringWriter sr = new StringWriter();
        sr.append("<@renderPortalPageBegin ");
        sr.append("originalPortalPageId=\"");
        sr.append(originalPortalPageId);
        sr.append("\" portalPageId=\"");
        sr.append(portalPageId);
        sr.append("\" confMode=\"");
        sr.append(confMode);
        sr.append("\" addColumnLabel=\"");
        sr.append(addColumnLabel);
        sr.append("\" addColumnHint=\"");
        sr.append(addColumnHint);
        sr.append("\" />");
        executeMacro(writer, sr.toString());
    }

    @Override
    public void renderPortalPageEnd(Appendable writer, Map<String, Object> context, ModelScreenWidget.PortalPage portalPage)
            throws GeneralException, IOException {
        StringWriter sr = new StringWriter();
        sr.append("<@renderPortalPageEnd/>");
        executeMacro(writer, sr.toString());
    }

    @Override
    public void renderPortalPageColumnBegin(Appendable writer, Map<String, Object> context, ModelScreenWidget.PortalPage portalPage,
                                            GenericValue portalPageColumn) throws GeneralException, IOException {
        String portalPageId = portalPage.getActualPortalPageId(context);
        String originalPortalPageId = portalPage.getOriginalPortalPageId(context);
        String columnSeqId = portalPageColumn.getString("columnSeqId");
        String columnWidthPercentage = portalPageColumn.getString("columnWidthPercentage");
        String columnWidthPixels = portalPageColumn.getString("columnWidthPixels");
        String confMode = portalPage.getConfMode(context);

        Map<String, String> uiLabelMap = UtilGenerics.cast(context.get("uiLabelMap"));
        String delColumnLabel = "";
        String delColumnHint = "";
        String addPortletLabel = "";
        String addPortletHint = "";
        String colWidthLabel = "";
        String setColumnSizeHint = "";

        if (uiLabelMap == null) {
            Debug.logWarning("Could not find uiLabelMap in context", MODULE);
        } else {
            delColumnLabel = uiLabelMap.get("CommonDeleteColumn");
            delColumnHint = uiLabelMap.get("CommonDeleteThisColumn");

            addPortletLabel = uiLabelMap.get("CommonAddAPortlet");
            addPortletHint = uiLabelMap.get("CommonAddPortletToPage");
            colWidthLabel = uiLabelMap.get("CommonWidth");
            setColumnSizeHint = uiLabelMap.get("CommonSetColumnWidth");
        }

        StringWriter sr = new StringWriter();
        sr.append("<@renderPortalPageColumnBegin ");
        sr.append("originalPortalPageId=\"");
        sr.append(originalPortalPageId);
        sr.append("\" portalPageId=\"");
        sr.append(portalPageId);
        sr.append("\" columnSeqId=\"");
        sr.append(columnSeqId);
        sr.append("\" ");
        if (UtilValidate.isNotEmpty(columnWidthPixels)) {
            sr.append("width=\"");
            sr.append(columnWidthPixels);
            sr.append("px\"");
        } else if (UtilValidate.isNotEmpty(columnWidthPercentage)) {
            sr.append("width=\"");
            sr.append(columnWidthPercentage);
            sr.append("%\"");
        }
        sr.append(" confMode=\"");
        sr.append(confMode);
        sr.append("\" delColumnLabel=\"");
        sr.append(delColumnLabel);
        sr.append("\" delColumnHint=\"");
        sr.append(delColumnHint);
        sr.append("\" addPortletLabel=\"");
        sr.append(addPortletLabel);
        sr.append("\" addPortletHint=\"");
        sr.append(addPortletHint);
        sr.append("\" colWidthLabel=\"");
        sr.append(colWidthLabel);
        sr.append("\" setColumnSizeHint=\"");
        sr.append(setColumnSizeHint);
        sr.append("\" />");
        executeMacro(writer, sr.toString());
    }

    @Override
    public void renderPortalPageColumnEnd(Appendable writer, Map<String, Object> context, ModelScreenWidget.PortalPage portalPage,
                                          GenericValue portalPageColumn) throws GeneralException, IOException {
        StringWriter sr = new StringWriter();
        sr.append("<@renderPortalPageColumnEnd/>");
        executeMacro(writer, sr.toString());
    }

    @Override
    public void renderPortalPagePortletBegin(Appendable writer, Map<String, Object> context, ModelScreenWidget.PortalPage portalPage,
                                             GenericValue portalPortlet) throws GeneralException, IOException {
        String portalPageId = portalPage.getActualPortalPageId(context);
        String originalPortalPageId = portalPage.getOriginalPortalPageId(context);
        String portalPortletId = portalPortlet.getString("portalPortletId");
        String portletSeqId = portalPortlet.getString("portletSeqId");
        String columnSeqId = portalPortlet.getString("columnSeqId");
        String confMode = portalPage.getConfMode(context);
        String editFormName = portalPortlet.getString("editFormName");
        String editFormLocation = portalPortlet.getString("editFormLocation");

        String prevPortletId = (String) context.get("prevPortletId");
        String prevPortletSeqId = (String) context.get("prevPortletSeqId");
        String nextPortletId = (String) context.get("nextPortletId");
        String nextPortletSeqId = (String) context.get("nextPortletSeqId");
        String prevColumnSeqId = (String) context.get("prevColumnSeqId");
        String nextColumnSeqId = (String) context.get("nextColumnSeqId");

        Map<String, String> uiLabelMap = UtilGenerics.cast(context.get("uiLabelMap"));
        String delPortletHint = "";
        String editAttributeHint = "";
        if (uiLabelMap == null) {
            Debug.logWarning("Could not find uiLabelMap in context", MODULE);
        } else {
            delPortletHint = uiLabelMap.get("CommonDeleteThisPortlet");
            editAttributeHint = uiLabelMap.get("CommonEditPortletAttributes");
        }

        StringWriter sr = new StringWriter();
        sr.append("<@renderPortalPagePortletBegin ");
        sr.append("originalPortalPageId=\"");
        sr.append(originalPortalPageId);
        sr.append("\" portalPageId=\"");
        sr.append(portalPageId);
        sr.append("\" portalPortletId=\"");
        sr.append(portalPortletId);
        sr.append("\" portletSeqId=\"");
        sr.append(portletSeqId);
        sr.append("\" prevPortletId=\"");
        sr.append(prevPortletId);
        sr.append("\" prevPortletSeqId=\"");
        sr.append(prevPortletSeqId);
        sr.append("\" nextPortletId=\"");
        sr.append(nextPortletId);
        sr.append("\" nextPortletSeqId=\"");
        sr.append(nextPortletSeqId);
        sr.append("\" columnSeqId=\"");
        sr.append(columnSeqId);
        sr.append("\" prevColumnSeqId=\"");
        sr.append(prevColumnSeqId);
        sr.append("\" nextColumnSeqId=\"");
        sr.append(nextColumnSeqId);
        sr.append("\" delPortletHint=\"");
        sr.append(delPortletHint);
        sr.append("\" editAttributeHint=\"");
        sr.append(editAttributeHint);
        sr.append("\" confMode=\"");
        sr.append(confMode);
        sr.append("\"");
        if (UtilValidate.isNotEmpty(editFormName) && UtilValidate.isNotEmpty(editFormLocation)) {
            sr.append(" editAttribute=\"true\"");
        }
        sr.append("/>");
        executeMacro(writer, sr.toString());
    }

    @Override
    public void renderPortalPagePortletEnd(Appendable writer, Map<String, Object> context, ModelScreenWidget.PortalPage portalPage,
                                           GenericValue portalPortlet) throws GeneralException, IOException {
        String confMode = portalPage.getConfMode(context);

        StringWriter sr = new StringWriter();
        sr.append("<@renderPortalPagePortletEnd ");
        sr.append(" confMode=\"");
        sr.append(confMode);
        sr.append("\" />");
        executeMacro(writer, sr.toString());
    }

    @Override
    public void renderPortalPagePortletBody(Appendable writer, Map<String, Object> context, ModelScreenWidget.PortalPage portalPage,
                                            GenericValue portalPortlet) throws GeneralException, IOException {
        String portalPortletId = portalPortlet.getString("portalPortletId");
        String screenName = portalPortlet.getString("screenName");
        String screenLocation = portalPortlet.getString("screenLocation");

        ModelScreen modelScreen = null;
        if (UtilValidate.isNotEmpty(screenName) && UtilValidate.isNotEmpty(screenLocation)) {
            try {
                context.put("portalPortletId", portalPortlet.getString("portalPortletId"));
                context.put("portletSeqId", portalPortlet.getString("portletSeqId"));
                modelScreen = ScreenFactory.getScreenFromLocation(screenLocation, screenName);
            } catch (IOException | SAXException | ParserConfigurationException e) {
                String errMsg = "Error rendering portlet ID [" + portalPortletId + "]: " + e.toString();
                Debug.logError(e, errMsg, MODULE);
                throw new RuntimeException(errMsg);
            }
        }
        if (writer != null && context != null) {
            modelScreen.renderScreenString(writer, context, this);
        } else {
            Debug.logError("Null on some Path: writer" + writer + ", context: " + context, MODULE);
        }
    }

    @Override
    public void renderColumnContainer(Appendable writer, Map<String, Object> context, ColumnContainer columnContainer) throws IOException {
        String id = columnContainer.getId(context);
        String style = columnContainer.getStyle(context);
        StringBuilder sb = new StringBuilder("<@renderColumnContainerBegin");
        sb.append(" id=\"");
        sb.append(id);
        sb.append("\" style=\"");
        sb.append(style);
        sb.append("\" />");
        executeMacro(writer, sb.toString());
        for (Column column : columnContainer.getColumns()) {
            id = column.getId(context);
            style = column.getStyle(context);
            sb = new StringBuilder("<@renderColumnBegin");
            sb.append(" id=\"");
            sb.append(id);
            sb.append("\" style=\"");
            sb.append(style);
            sb.append("\" />");
            executeMacro(writer, sb.toString());
            for (ModelScreenWidget subWidget : column.getSubWidgets()) {
                try {
                    subWidget.renderWidgetString(writer, context, this);
                } catch (GeneralException e) {
                    throw new IOException(e);
                }
            }
            executeMacro(writer, "<@renderColumnEnd />");
        }
        executeMacro(writer, "<@renderColumnContainerEnd />");
    }

    // This is a util method to get the style from a property file
    public static String getFoStyle(String styleName) {
        String value = UtilProperties.getPropertyValue("fo-styles", styleName);
        if (value.equals(styleName)) {
            return "";
        }
        return value;
    }
}
