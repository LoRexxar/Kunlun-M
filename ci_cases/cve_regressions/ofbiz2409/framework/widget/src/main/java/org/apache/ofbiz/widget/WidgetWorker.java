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
package org.apache.ofbiz.widget;

import java.util.Map;

import javax.servlet.ServletContext;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.apache.http.client.utils.URIBuilder;
import org.apache.ofbiz.base.util.Debug;
import org.apache.ofbiz.base.util.UtilHttp;
import org.apache.ofbiz.security.CsrfUtil;
import org.apache.ofbiz.base.util.UtilGenerics;
import org.apache.ofbiz.base.util.UtilValidate;
import org.apache.ofbiz.entity.Delegator;
import org.apache.ofbiz.service.LocalDispatcher;
import org.apache.ofbiz.webapp.control.ConfigXMLReader;
import org.apache.ofbiz.webapp.control.RequestHandler;
import org.apache.ofbiz.webapp.taglib.ContentUrlTag;
import org.apache.ofbiz.widget.model.CommonWidgetModels;
import org.apache.ofbiz.widget.model.ModelForm;
import org.apache.ofbiz.widget.model.ModelFormField;
import org.apache.ofbiz.widget.renderer.ScreenRenderer;
import org.jsoup.nodes.Element;
import org.jsoup.nodes.FormElement;
import org.jsoup.parser.Parser;
import org.jsoup.parser.Tag;

import java.net.URI;
import java.net.URISyntaxException;
import java.util.HashMap;

import static org.apache.ofbiz.base.util.UtilValidate.isNotEmpty;

public final class WidgetWorker {

    private static final String MODULE = WidgetWorker.class.getName();

    private WidgetWorker() { }

    public static URI buildHyperlinkUri(String target, String targetType, Map<String, String> parameterMap,
                                        String prefix, boolean fullPath, boolean secure, boolean encode,
                                        HttpServletRequest request, HttpServletResponse response) {
        // We may get an encoded request like: &#47;projectmgr&#47;control&#47;EditTaskContents&#63;workEffortId&#61;10003
        // Try to reducing a possibly encoded string down to its simplest form: /projectmgr/control/EditTaskContents?workEffortId=10003
        // This step make sure the following appending externalLoginKey operation to work correctly
        String localRequestName = Parser.unescapeEntities(target, true);

        // To handle cases where target contains javascript we need to encode spaces.
        // Example:  "javascript:set_value('system', 'system', '')" becomes "javascript:set_value('system',%20'system',%20'')
        localRequestName = UtilHttp.encodeBlanks(localRequestName);

        final URIBuilder uriBuilder;
        final Map<String, String> additionalParameters = new HashMap<>();
        final String uriString;

        if ("intra-app".equals(targetType)) {
            if (request != null && response != null) {
                ServletContext servletContext = request.getSession().getServletContext();
                RequestHandler rh = (RequestHandler) servletContext.getAttribute("_REQUEST_HANDLER_");

                uriString = rh.makeLink(request, response, "/" + localRequestName, fullPath, secure, encode);
            } else if (prefix != null) {
                uriString = prefix + localRequestName;
            } else {
                uriString = localRequestName;
            }
        } else if ("inter-app".equals(targetType)) {
            uriString = localRequestName;
            String externalLoginKey = (String) request.getAttribute("externalLoginKey");
            additionalParameters.put("externalLoginKey", externalLoginKey);
        } else if ("content".equals(targetType)) {
            uriString = getContentUrl(localRequestName, request);
        } else {
            uriString = localRequestName;
        }

        try {
            uriBuilder = new URIBuilder(uriString);
        } catch (URISyntaxException e) {
            final String msg = "Syntax error when parsing URI: " + uriString;
            Debug.logError(e, msg, MODULE);
            throw new RuntimeException(msg, e);
        }

        if (!"plain".equals(targetType)) {
            final String tokenValue = CsrfUtil.generateTokenForNonAjax(request, target);
            if (isNotEmpty(tokenValue)) {
                additionalParameters.put(CsrfUtil.getTokenNameNonAjax(), tokenValue);
            }

            if (UtilValidate.isNotEmpty(parameterMap)) {
                parameterMap.forEach(uriBuilder::addParameter);
            }

            additionalParameters.forEach(uriBuilder::addParameter);
        }
        try {
            return uriBuilder.build();
        } catch (URISyntaxException e) {
            final String msg = "Syntax error when building URI: " + uriBuilder.toString();
            Debug.logError(e, msg, MODULE);
            throw new RuntimeException(msg, e);
        }
    }

    public static String getContentUrl(final String location, final HttpServletRequest request) {
        StringBuilder buffer = new StringBuilder();
        ContentUrlTag.appendContentPrefix(request, buffer);
        buffer.append(location);
        return buffer.toString();
    }

    public static Element makeHiddenFormLinkAnchorElement(String linkStyle, String description, String confirmation,
                                                          ModelFormField modelFormField, HttpServletRequest request,
                                                          Map<String, Object> context) {
        if (isNotEmpty(description) || isNotEmpty(request.getAttribute("image"))) {
            final Element anchorElement = new Element("a");

            if (isNotEmpty(linkStyle)) {
                anchorElement.addClass(linkStyle);
            }

            final String href = "javascript:document." + makeLinkHiddenFormName(context, modelFormField) + ".submit()";
            anchorElement.attr("href", href);

            if (isNotEmpty(modelFormField.getEvent()) && isNotEmpty(modelFormField.getAction(context))) {
                anchorElement.attr(modelFormField.getEvent(), modelFormField.getAction(context));
            }

            if (isNotEmpty(confirmation)) {
                anchorElement.attr("onclick", "return confirm('" + confirmation + "')");
            }

            int size = 0;
            String title = request.getAttribute("title").toString();
            if (UtilValidate.isNotEmpty(request.getAttribute("descriptionSize"))) {
                size = Integer.parseInt(request.getAttribute("descriptionSize").toString());
            }

            // if description is truncated, always use description as title
            if (UtilValidate.isNotEmpty(description) && size > 0 && description.length() > size) {
                title = description;
                description = description.substring(0, size) + "…";
            }

            if (isNotEmpty(title)) {
                anchorElement.attr("title", title);
            }

            anchorElement.text(description);

            if (isNotEmpty(request.getAttribute("image"))) {
                final Element imageElement = new Element("img");
                imageElement.attr("src", request.getAttribute("image").toString());

                anchorElement.appendChild(imageElement);
            }

            return anchorElement;
        } else {
            return null;
        }
    }

    public static Element makeHiddenFormLinkFormElement(String target, String targetType,
                                              String targetWindow, Map<String, String> parameterMap,
                                              ModelFormField modelFormField, HttpServletRequest request,
                                              HttpServletResponse response, Map<String, Object> context) {

        final FormElement formElement = new FormElement(Tag.valueOf("form"), null, null);
        formElement.attr("method", "post");

        // note that this passes null for the parameterList on purpose so they won't be put into the URL
        final URI actionUri = WidgetWorker.buildHyperlinkUri(target, targetType, null, null, false, false, true,
                request, response);
        formElement.attr("action", actionUri.toString());

        if (isNotEmpty(targetWindow)) {
            formElement.attr("target", targetWindow);
        }

        formElement.attr("onsubmit", "javascript:submitFormDisableSubmits(this)");
        formElement.attr("name", makeLinkHiddenFormName(context, modelFormField));

        parameterMap.forEach((name, value) -> formElement.appendElement("input")
                .attr("name", name)
                .val(value)
                .attr("type", "hidden"));

        return formElement;
    }

    public static String makeLinkHiddenFormName(Map<String, Object> context, ModelFormField modelFormField) {
        ModelForm modelForm = modelFormField.getModelForm();
        Integer itemIndex = (Integer) context.get("itemIndex");
        String iterateId = "";
        String formUniqueId = "";
        String formName = (String) context.get("formName");
        if (UtilValidate.isEmpty(formName)) {
            formName = modelForm.getName();
        }
        if (UtilValidate.isNotEmpty(context.get("iterateId"))) {
            iterateId = (String) context.get("iterateId");
        }
        if (UtilValidate.isNotEmpty(context.get("formUniqueId"))) {
            formUniqueId = (String) context.get("formUniqueId");
        }
        if (itemIndex != null) {
            return formName + modelForm.getItemIndexSeparator() + itemIndex + iterateId + formUniqueId
                    + modelForm.getItemIndexSeparator() + modelFormField.getName();
        }
        return formName + modelForm.getItemIndexSeparator() + modelFormField.getName();
    }

    public static String determineAutoLinkType(String linkType, String target, String targetType, HttpServletRequest request) {
        if ("auto".equals(linkType)) {
            if ("intra-app".equals(targetType)) {
                String requestUri = (target.indexOf('?') > -1) ? target.substring(0, target.indexOf('?')) : target;
                ServletContext servletContext = request.getSession().getServletContext();
                RequestHandler rh = (RequestHandler) servletContext.getAttribute("_REQUEST_HANDLER_");
                ConfigXMLReader.RequestMap requestMap = rh.getControllerConfig().getRequestMapMap().get(requestUri);
                if (requestMap != null && requestMap.getEvent() != null) {
                    return "hidden-form";
                }
            }
            return "anchor";
        }
        return linkType;
    }

    /** Returns the script location based on a script combined name:
     * <code>location#methodName</code>.
     * @param combinedName The combined location/method name
     * @return The script location
     */
    public static String getScriptLocation(String combinedName) {
        int pos = combinedName.lastIndexOf('#');
        if (pos == -1) {
            return combinedName;
        }
        return combinedName.substring(0, pos);
    }

    /** Returns the script method name based on a script combined name:
     * <code>location#methodName</code>. Returns <code>null</code> if
     * no method name is found.
     * @param combinedName The combined location/method name
     * @return The method name or <code>null</code>
     */
    public static String getScriptMethodName(String combinedName) {
        int pos = combinedName.lastIndexOf('#');
        if (pos == -1) {
            return null;
        }
        return combinedName.substring(pos + 1);
    }

    /**
     * Returns the ScreenStack from the context.
     * If none, init new one and return it.
     * @param context
     * @return
     */
    public static ScreenRenderer.ScreenStack getScreenStack(Map<String, Object> context) {
        if (!context.containsKey("screenStack")) {
            context.put("screenStack", new ScreenRenderer.ScreenStack());
        }
        return (ScreenRenderer.ScreenStack) context.get("screenStack");
    }

    /**
     * Returns the jwt callback id if present on the context.
     * @param context
     * @return
     */
    public static String getJwtCallback(Map<String, Object> context) {
        String jwtCallback = (String) context.get(CommonWidgetModels.JWT_CALLBACK);
        if (UtilValidate.isEmpty(jwtCallback) && context.containsKey("parameters")) {
            jwtCallback = (String) ((Map) context.get("parameters")).get(CommonWidgetModels.JWT_CALLBACK);
        }
        return jwtCallback;
    }

    public static int getPaginatorNumber(Map<String, Object> context) {
        int paginatorNumber = 0;
        if (context != null) {
            Integer paginateNumberInt = (Integer) context.get("PAGINATOR_NUMBER");
            if (paginateNumberInt == null) {
                paginateNumberInt = 0;
                context.put("PAGINATOR_NUMBER", paginateNumberInt);
                Map<String, Object> globalCtx = UtilGenerics.cast(context.get("globalContext"));
                if (globalCtx != null) {
                    globalCtx.put("PAGINATOR_NUMBER", paginateNumberInt);
                }
            }
            paginatorNumber = paginateNumberInt;
        }
        return paginatorNumber;
    }

    public static void incrementPaginatorNumber(Map<String, Object> context) {
        Map<String, Object> globalCtx = UtilGenerics.cast(context.get("globalContext"));
        if (globalCtx != null) {
            Boolean noPaginator = (Boolean) globalCtx.get("NO_PAGINATOR");
            if (UtilValidate.isNotEmpty(noPaginator)) {
                globalCtx.remove("NO_PAGINATOR");
            } else {
                Integer paginateNumberInt = (Integer) globalCtx.get("PAGINATOR_NUMBER");
                if (paginateNumberInt == null) {
                    paginateNumberInt = 0;
                }
                paginateNumberInt = paginateNumberInt + 1;
                globalCtx.put("PAGINATOR_NUMBER", paginateNumberInt);
                context.put("PAGINATOR_NUMBER", paginateNumberInt);
            }
        }
    }

    public static LocalDispatcher getDispatcher(Map<String, Object> context) {
        return (LocalDispatcher) context.get("dispatcher");
    }

    public static Delegator getDelegator(Map<String, Object> context) {
        return (Delegator) context.get("delegator");
    }

    /**
     * Analyse the context to found the _QBESTRING_ parameter and return it as Map
     * @param context
     * @return
     */
    public static Map<String, Object> resolveParametersMapFromQueryString(Map<String, Object> context) {
        String qbeString = (String) context.get("_QBESTRING_");
        return qbeString != null
                ? UtilHttp.getQueryStringOnlyParameterMap(qbeString.replace("&amp;", "&"))
                : null;
    }
}
