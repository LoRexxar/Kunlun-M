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
package org.apache.ofbiz.base.util;

import static java.util.stream.Collectors.collectingAndThen;
import static java.util.stream.Collectors.groupingBy;
import static java.util.stream.Collectors.mapping;
import static java.util.stream.Collectors.toList;
import static java.util.stream.Collectors.toMap;

import java.io.BufferedInputStream;
import java.io.BufferedOutputStream;
import java.io.ByteArrayInputStream;
import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.io.UnsupportedEncodingException;
import java.net.FileNameMap;
import java.net.URI;
import java.net.URISyntaxException;
import java.net.URLConnection;
import java.net.URLDecoder;
import java.net.URLEncoder;
import java.nio.ByteBuffer;
import java.nio.charset.Charset;
import java.sql.Timestamp;
import java.time.LocalDateTime;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.Collections;
import java.util.Currency;
import java.util.Enumeration;
import java.util.HashMap;
import java.util.HashSet;
import java.util.LinkedList;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import java.util.Set;
import java.util.StringTokenizer;
import java.util.TimeZone;
import java.util.function.Function;
import java.util.function.Predicate;
import java.util.stream.Collectors;
import java.util.stream.Stream;

import javax.net.ssl.SSLContext;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;

import org.apache.commons.fileupload.FileItem;
import org.apache.commons.fileupload.FileUploadException;
import org.apache.commons.fileupload.disk.DiskFileItemFactory;
import org.apache.commons.fileupload.servlet.ServletFileUpload;
import org.apache.commons.lang.RandomStringUtils;
import org.apache.http.NameValuePair;
import org.apache.http.client.utils.URLEncodedUtils;
import org.apache.http.conn.ssl.NoopHostnameVerifier;
import org.apache.http.conn.ssl.SSLConnectionSocketFactory;
import org.apache.http.conn.ssl.TrustSelfSignedStrategy;
import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.impl.client.HttpClients;
import org.apache.http.ssl.SSLContexts;
import org.apache.ofbiz.entity.Delegator;
import org.apache.ofbiz.entity.util.EntityUtilProperties;
import org.apache.ofbiz.webapp.control.ConfigXMLReader;
import org.apache.ofbiz.webapp.control.SameSiteFilter;
import org.apache.ofbiz.webapp.event.FileUploadProgressListener;
import org.apache.ofbiz.widget.renderer.VisualTheme;

import com.google.re2j.Matcher;
import com.google.re2j.Pattern;

/**
 * HttpUtil - Misc HTTP Utility Functions
 */
public final class UtilHttp {

    private static final String MODULE = UtilHttp.class.getName();

    private static final String MULTI_ROW_DELIMITER = "_o_";
    private static final String ROW_SUBMIT_PREFIX = "_rowSubmit_o_";
    private static final String COMPOSITE_DELIMITER = "_c_";
    private static final int MULTI_ROW_DELIMITER_LENGTH = MULTI_ROW_DELIMITER.length();
    private static final int ROW_SUBMIT_PREFIX_LENGTH = ROW_SUBMIT_PREFIX.length();

    private static final String SESSION_KEY_TIMEZONE = "timeZone";
    private static final String SESSION_KEY_THEME = "visualTheme";

    private UtilHttp() { }

    /**
     * Create a combined map from servlet context, session, attributes and parameters
     * @return The resulting Map
     */
    public static Map<String, Object> getCombinedMap(HttpServletRequest request) {
        return getCombinedMap(request, null);
    }

    /**
     * Create a combined map from servlet context, session, attributes and parameters
     * -- this method will only use the skip names for session and servlet context attributes
     * @return The resulting Map
     */
    public static Map<String, Object> getCombinedMap(HttpServletRequest request, Set<? extends String> namesToSkip) {
        Map<String, Object> combinedMap = new HashMap<>();
        combinedMap.putAll(getParameterMap(request));                   // parameters override nothing
        combinedMap.putAll(getServletContextMap(request, namesToSkip)); // bottom level application attributes
        combinedMap.putAll(getSessionMap(request, namesToSkip));        // session overrides application
        combinedMap.putAll(getAttributeMap(request));                   // attributes trump them all

        return combinedMap;
    }

    /**
     * Creates a canonicalized parameter map from a HTTP request.
     * <p>
     * If parameters are empty, the multi-part parameter map will be used.
     * @param request the HTTP request containing the parameters
     * @return a canonicalized parameter map.
     */
    public static Map<String, Object> getParameterMap(HttpServletRequest request) {
        return getParameterMap(request, x -> true);
    }

    /**
     * Creates a canonicalized parameter map from a HTTP request.
     * <p>
     * If parameters are empty, the multi-part parameter map will be used.
     * @param req the HTTP request containing the parameters
     * @param pred the predicate filtering the parameter names
     * @return a canonicalized parameter map.
     */
    public static Map<String, Object> getParameterMap(HttpServletRequest req, Predicate<String> pred) {
        // Add all the actual HTTP request parameters
        Map<String, String[]> origParams = req.getParameterMap();
        Map<String, Object> params = origParams.entrySet().stream()
                .filter(pair -> pred.test(pair.getKey()))
                .collect(toMap(Map.Entry::getKey, pair -> transformParamValue(pair.getValue())));

        // Pseudo-parameters passed in the URI path overrides the ones from the regular URI parameters
        params.putAll(getPathInfoOnlyParameterMap(req.getPathInfo(), pred));

        // If nothing is found in the parameters, try to find something in the multi-part map.
        Map<String, Object> multiPartMap = params.isEmpty() ? getMultiPartParameterMap(req) : Collections.emptyMap();
        params.putAll(multiPartMap);
        if (req.getAttribute("multiPartMap") == null) {
            req.setAttribute("multiPartMap", multiPartMap);
        }
        if (Debug.verboseOn()) {
            Debug.logVerbose("Made Request Parameter Map with [" + params.size() + "] Entries", MODULE);
        }

        // Handles encoded queryStrings
        String requestURI = req.getRequestURI();
        if (params.isEmpty() && null != requestURI) {
            try {
                List<NameValuePair> nameValuePairs = URLEncodedUtils.parse(
                        new URI(UtilHttp.encodeBlanks(URLDecoder.decode(requestURI, "UTF-8"))),
                        Charset.forName("UTF-8"));
                for (NameValuePair element : nameValuePairs) {
                    params.put(element.getName(), element.getValue());
                }
            } catch (UnsupportedEncodingException | URISyntaxException e) {
                Debug.logError("Can't handle encoded queryString " + requestURI, MODULE);
            }
        }
        return canonicalizeParameterMap(params);
    }

    /**
     * Transforms a string array into either a list of string or string.
     * <p>
     * This is meant to facilitate the work of request handlers.
     * @param value the array of string to prepare
     * @return the adapted value.
     * @throws NullPointerException when {@code value} is {@code null}.
     */
    private static Object transformParamValue(String[] value) {
        return value.length == 1 ? value[0] : Arrays.asList(value);
    }

    public static Map<String, Object> getMultiPartParameterMap(HttpServletRequest request) {
        Map<String, Object> multiPartMap = new HashMap<>();
        Delegator delegator = (Delegator) request.getAttribute("delegator");
        HttpSession session = request.getSession();
        boolean isMultiPart = ServletFileUpload.isMultipartContent(request);
        if (isMultiPart) {
            long maxUploadSize = getMaxUploadSize(delegator);
            int sizeThreshold = getSizeThreshold(delegator);
            File tmpUploadRepository = getTmpUploadRepository(delegator);
            String encoding = request.getCharacterEncoding();
            // check for multipart content types which may have uploaded items

            ServletFileUpload upload = new ServletFileUpload(new DiskFileItemFactory(sizeThreshold, tmpUploadRepository));
            upload.setSizeMax(maxUploadSize);
            // create the progress listener and add it to the session
            FileUploadProgressListener listener = new FileUploadProgressListener();
            upload.setProgressListener(listener);
            session.setAttribute("uploadProgressListener", listener);

            if (encoding != null) {
                upload.setHeaderEncoding(encoding);
            }

            List<FileItem> uploadedItems = null;
            try {
                uploadedItems = UtilGenerics.cast(upload.parseRequest(request));
            } catch (FileUploadException e) {
                Debug.logError("File upload error" + e, MODULE);
            }
            if (uploadedItems != null) {
                request.setAttribute("fileItems", uploadedItems);
                for (FileItem item : uploadedItems) {
                    String fieldName = item.getFieldName();
                    //byte[] itemBytes = item.get();
                    /*
                    Debug.logInfo("Item Info [" + fieldName + "] : " + item.getName() + " / " + item.getSize() + " / " +
                            item.getContentType() + " FF: " + item.isFormField(), MODULE);
                    */
                    if (item.isFormField() || item.getName() == null) {
                        if (multiPartMap.containsKey(fieldName)) {
                            Object mapValue = multiPartMap.get(fieldName);
                            if (mapValue instanceof List<?>) {
                                UtilGenerics.checkCollection(mapValue, Object.class).add(item.getString());
                            } else if (mapValue instanceof String) {
                                List<String> newList = new LinkedList<>();
                                newList.add((String) mapValue);
                                newList.add(item.getString());
                                multiPartMap.put(fieldName, newList);
                            } else {
                                Debug.logWarning("Form field found [" + fieldName + "] which was not handled!", MODULE);
                            }
                        } else {
                            if (encoding != null) {
                                try {
                                    multiPartMap.put(fieldName, item.getString(encoding));
                                } catch (java.io.UnsupportedEncodingException uee) {
                                    Debug.logError(uee, "Unsupported Encoding, using deafault", MODULE);
                                    multiPartMap.put(fieldName, item.getString());
                                }
                            } else {
                                multiPartMap.put(fieldName, item.getString());
                            }
                        }
                        /* OFBIZ-10833 - Set the consumed parameters in request attributes for enctype="multipart/form-data" type form
                         * so that it will be available for the next response. Please refer Jira for more details.
                         */
                        request.setAttribute(fieldName, multiPartMap.get(fieldName));
                    } else {
                        String fileName = item.getName();
                        if (fileName.indexOf('\\') > -1 || fileName.indexOf('/') > -1) {
                            // get just the file name IE and other browsers also pass in the local path
                            int lastIndex = fileName.lastIndexOf('\\');
                            if (lastIndex == -1) {
                                lastIndex = fileName.lastIndexOf('/');
                            }
                            if (lastIndex > -1) {
                                fileName = fileName.substring(lastIndex + 1);
                            }
                        }
                        multiPartMap.put(fieldName, ByteBuffer.wrap(item.get()));
                        multiPartMap.put("_" + fieldName + "_fileItem", item);
                        multiPartMap.put("_" + fieldName + "_size", item.getSize());
                        multiPartMap.put("_" + fieldName + "_fileName", fileName);
                        multiPartMap.put("_" + fieldName + "_contentType", item.getContentType());
                    }
                }
            }
        }

        return multiPartMap;
    }

    /**
     * @param delegator
     * @return maxUploadSize
     */
    public static long getMaxUploadSize(Delegator delegator) {
        // get the HTTP upload configuration
        String maxSizeStr = EntityUtilProperties.getPropertyValue("general", "http.upload.max.size", "-1", delegator);
        long maxUploadSize = -1;
        try {
            maxUploadSize = Long.parseLong(maxSizeStr);
        } catch (NumberFormatException e) {
            Debug.logError(e, "Unable to obtain the max upload size from general.properties; using default -1", MODULE);
            maxUploadSize = -1;
        }
        return maxUploadSize;
    }

    /**
     * @param delegator
     * @return sizeThreshold
     */
    public static int getSizeThreshold(Delegator delegator) {
        // get the HTTP size threshold configuration - files bigger than this will be
        // temporarily stored on disk during upload
        String sizeThresholdStr = EntityUtilProperties.getPropertyValue("general", "http.upload.max.sizethreshold",
                "10240", delegator);
        int sizeThreshold = 10240; // 10K
        try {
            sizeThreshold = Integer.parseInt(sizeThresholdStr);
        } catch (NumberFormatException e) {
            Debug.logError(e, "Unable to obtain the threshold size from general.properties; using default 10K", MODULE);
            sizeThreshold = -1;
        }
        return sizeThreshold;
    }

    /**
     * @param delegator
     * @return tmpUploadRepository
     */
    public static File getTmpUploadRepository(Delegator delegator) {
        // directory used to temporarily store files that are larger than the configured size threshold
        String tmpUploadRepository = EntityUtilProperties.getPropertyValue("general", "http.upload.tmprepository",
                "runtime/tmp", delegator);
        return new File(tmpUploadRepository);
    }

    public static Map<String, Object> getQueryStringOnlyParameterMap(String queryString) {
        Map<String, Object> paramMap = new HashMap<>();
        if (UtilValidate.isNotEmpty(queryString)) {
            StringTokenizer queryTokens = new StringTokenizer(queryString, "&");
            while (queryTokens.hasMoreTokens()) {
                String token = queryTokens.nextToken();
                if (token.startsWith("amp;")) {
                    // this is most likely a split value that had an &amp; in it, so don't consider this a name; note that some old code just
                    // stripped the "amp;" and went with it
                    continue;
                }
                int equalsIndex = token.indexOf("=");
                if (equalsIndex > 0) {
                    String name = token.substring(0, equalsIndex);
                    String paramValue = UtilCodec.getDecoder("url").decode(token.substring(equalsIndex + 1));
                    if (UtilValidate.isEmpty(paramMap.get(name))) {
                        paramMap.put(name, paramValue);
                    } else {
                        if (paramMap.get(name) instanceof Collection<?>) {
                            List<String> valueList = UtilGenerics.cast(paramMap.get(name));
                            valueList.add(paramValue);
                            paramMap.put(name, valueList);
                        } else {
                            paramMap.put(name, UtilMisc.toList(paramMap.get(name), paramValue));
                        }
                    }
                }
            }
        }
        return canonicalizeParameterMap(paramMap);
    }

    /**
     * Extracts the parameters that are passed in the URI path.
     * <p>
     * path parameters are denoted by "/~KEY0=VALUE0/~KEY1=VALUE1/".
     * This is an obsolete syntax for passing parameters to request handlers.
     * @param path the URI path part which can be {@code null}
     * @param pred the predicate filtering parameter names
     * @return a canonicalized parameter map.
     */
    public static Map<String, Object> getPathInfoOnlyParameterMap(String path, Predicate<String> pred) {
        String path1 = Optional.ofNullable(path).orElse("");
        Map<String, List<String>> allParams = Arrays.stream(path1.split("/"))
                .filter(segment -> segment.startsWith("~") && segment.contains("="))
                .map(kv -> kv.substring(1).split("="))
                .collect(groupingBy(kv -> kv[0], mapping(kv -> kv[1], toList())));

        // Filter and canonicalize the parameter map.
        Function<List<String>, Object> canonicalize = val -> (val.size() == 1) ? val.get(0) : val;
        return allParams.entrySet().stream()
                .filter(pair -> pred.test(pair.getKey()))
                .collect(collectingAndThen(toMap(Map.Entry::getKey, canonicalize.compose(Map.Entry::getValue)),
                        UtilHttp::canonicalizeParameterMap));
    }

    public static Map<String, Object> getUrlOnlyParameterMap(HttpServletRequest request) {
        // NOTE: these have already been through canonicalizeParameterMap, so not doing it again here
        Map<String, Object> paramMap = getQueryStringOnlyParameterMap(request.getQueryString());
        paramMap.putAll(getPathInfoOnlyParameterMap(request.getPathInfo(), x -> true));
        return paramMap;
    }

    public static Map<String, Object> canonicalizeParameterMap(Map<String, Object> paramMap) {
        for (Map.Entry<String, Object> paramEntry : paramMap.entrySet()) {
            if (paramEntry.getValue() instanceof String) {
                String paramEntries = (String) paramEntry.getValue();
                String[] stringValues = paramEntries.split(" ");
                String params = "";
                // Handles textareas, see OFBIZ-12249
                if (stringValues.length > 0 && !paramEntry.getKey().equals("DUMMYPAGE")) {
                    for (String s : stringValues) {
                        // if the string contains only an URL beginning by http or ftp => no change to keep special chars
                        // if the string contains only an URL beginning by http or ftp => no change to keep special chars
                        if (UtilValidate.isValidUrl(s)) {
                            params = params + s + " ";
                        } else if (UtilValidate.isUrlInString(s) && !s.isEmpty()) {
                            // if the string contains not only an URL => concatenate possible canonicalized before and after, w/o changing the URL
                            List<String> extractedUrls = extractUrls(s);
                            if (!extractedUrls.isEmpty()) {
                                String url = extractedUrls.get(0); // There should be only 1 URL in a block, makes no sense else
                                int start = s.indexOf(url);
                                String after = (String) s.subSequence(start + url.length(), s.length());
                                params = params + canonicalizeParameter((String) s.subSequence(0, start)) + url + canonicalizeParameter(after) + " ";
                            } else {
                                params = params + canonicalizeParameter(s) + " ";
                            }
                        } else {
                            // Simple string to canonicalize
                            params = params + canonicalizeParameter(s) + " ";
                        }
                    }
                    paramEntry.setValue(params.trim());
                } else {
                    paramEntry.setValue(canonicalizeParameter(paramEntries));
                }
            } else if (paramEntry.getValue() instanceof Collection<?>) {
                List<String> newList = new LinkedList<>();
                for (String listEntry : UtilGenerics.<Collection<String>>cast(paramEntry.getValue())) {
                    newList.add(canonicalizeParameter(listEntry));
                }
                paramEntry.setValue(newList);
            }
        }
        return paramMap;
    }

    public static String canonicalizeParameter(String paramValue) {
        try {
            /** calling canonicalize with strict flag set to false so we only get warnings about double encoding, etc; can be set to true for
             * exceptions and more security */
            String cannedStr = UtilCodec.canonicalize(paramValue, false);
            if (Debug.verboseOn()) {
                Debug.logVerbose("Canonicalized parameter with " + (cannedStr.equals(paramValue) ? "no " : "") + "change: original ["
                        + paramValue + "] canned [" + cannedStr + "]", MODULE);
            }
            return cannedStr;
        } catch (Exception e) {
            Debug.logError(e, "Error in canonicalize parameter value [" + paramValue + "]: " + e.toString(), MODULE);
            return paramValue;
        }
    }

    /**
     * Create a map from a HttpRequest (attributes) object used in JSON requests
     * @return The resulting Map
     */
    public static Map<String, Object> getJSONAttributeMap(HttpServletRequest request) {
        return parseJSONAttributeMap(getAttributeMap(request));
    }

    /**
     * For a map analyse each object to prepare a Json response
     * @param attrMap
     * @return
     */
    private static Map<String, Object> parseJSONAttributeMap(Map<String, Object> attrMap) {
        Map<String, Object> returnMap = new HashMap<>();
        for (Map.Entry<String, Object> entry : attrMap.entrySet()) {
            Object val = parseJSONAttributeValue(entry.getValue());
            if (val != null) {
                returnMap.put(entry.getKey(), val);
            }
        }
        return returnMap;
    }

    /**
     * For a value analyse the object type to prepare a Json response
     * @param val
     * @return
     */
    private static Object parseJSONAttributeValue(Object val) {
        if (val == null) {
            return null;
        }
        if (val instanceof java.sql.Timestamp) {
            val = val.toString();
        }
        if (val instanceof String
                || val instanceof Number
                || val instanceof Boolean) {
            return val;
        } else if (val instanceof Map<?, ?>) {
            return parseJSONAttributeMap(UtilGenerics.cast(val));
        } else if (val instanceof List<?>) {
            return ((List<?>) val).stream().map(UtilHttp::parseJSONAttributeValue).collect(Collectors.toList());
        }
        return null;
    }

    /**
     * Create a map from a HttpRequest (attributes) object
     * @return The resulting Map
     */
    public static Map<String, Object> getAttributeMap(HttpServletRequest request) {
        return getAttributeMap(request, null);
    }

    /**
     * Create a map from a HttpRequest (attributes) object
     * @return The resulting Map
     */
    public static Map<String, Object> getAttributeMap(HttpServletRequest request, Set<? extends String> namesToSkip) {
        Map<String, Object> attributeMap = new HashMap<>();

        // look at all request attributes
        Enumeration<String> requestAttrNames = UtilGenerics.cast(request.getAttributeNames());
        while (requestAttrNames.hasMoreElements()) {
            String attrName = requestAttrNames.nextElement();
            if (namesToSkip != null && namesToSkip.contains(attrName)) {
                continue;
            }

            Object attrValue = request.getAttribute(attrName);
            attributeMap.put(attrName, attrValue);
        }

        if (Debug.verboseOn()) {
            Debug.logVerbose("Made Request Attribute Map with [" + attributeMap.size() + "] Entries", MODULE);
            Debug.logVerbose("Request Attribute Map Entries: " + System.getProperty("line.separator") + UtilMisc.printMap(attributeMap), MODULE);
        }

        return attributeMap;
    }

    /**
     * Create a map from a HttpSession object
     * @return The resulting Map
     */
    public static Map<String, Object> getSessionMap(HttpServletRequest request) {
        return getSessionMap(request, null);
    }

    /**
     * Create a map from a HttpSession object
     * @return The resulting Map
     */
    public static Map<String, Object> getSessionMap(HttpServletRequest request, Set<? extends String> namesToSkip) {
        Map<String, Object> sessionMap = new HashMap<>();
        HttpSession session = request.getSession();

        // look at all the session attributes
        Enumeration<String> sessionAttrNames = UtilGenerics.cast(session.getAttributeNames());
        while (sessionAttrNames.hasMoreElements()) {
            String attrName = sessionAttrNames.nextElement();
            if (namesToSkip != null && namesToSkip.contains(attrName)) {
                continue;
            }

            Object attrValue = session.getAttribute(attrName);
            sessionMap.put(attrName, attrValue);
        }

        if (Debug.verboseOn()) {
            Debug.logVerbose("Made Session Attribute Map with [" + sessionMap.size() + "] Entries", MODULE);
            Debug.logVerbose("Session Attribute Map Entries: " + System.getProperty("line.separator") + UtilMisc.printMap(sessionMap), MODULE);
        }

        return sessionMap;
    }

    /**
     * Create a map from a ServletContext object
     * @return The resulting Map
     */
    public static Map<String, Object> getServletContextMap(HttpServletRequest request) {
        return getServletContextMap(request, null);
    }

    /**
     * Create a map from a ServletContext object
     * @return The resulting Map
     */
    public static Map<String, Object> getServletContextMap(HttpServletRequest request, Set<? extends String> namesToSkip) {
        Map<String, Object> servletCtxMap = new HashMap<>();

        // look at all servlet context attributes
        Enumeration<String> applicationAttrNames = request.getServletContext().getAttributeNames();
        while (applicationAttrNames.hasMoreElements()) {
            String attrName = applicationAttrNames.nextElement();
            if (namesToSkip != null && namesToSkip.contains(attrName)) {
                continue;
            }

            Object attrValue = request.getServletContext().getAttribute(attrName);
            servletCtxMap.put(attrName, attrValue);
        }

        if (Debug.verboseOn()) {
            Debug.logVerbose("Made ServletContext Attribute Map with [" + servletCtxMap.size() + "] Entries", MODULE);
            Debug.logVerbose("ServletContext Attribute Map Entries: " + System.getProperty("line.separator") + UtilMisc.printMap(servletCtxMap),
                    MODULE);
        }

        return servletCtxMap;
    }

    public static Map<String, Object> makeParamMapWithPrefix(HttpServletRequest request, String prefix, String suffix) {
        return makeParamMapWithPrefix(request, null, prefix, suffix);
    }

    public static Map<String, Object> makeParamMapWithPrefix(HttpServletRequest request, Map<String, ? extends Object> additionalFields,
                                                             String prefix, String suffix) {
        return makeParamMapWithPrefix(getCombinedMap(request), additionalFields, prefix, suffix);
    }

    public static Map<String, Object> makeParamMapWithPrefix(Map<String, ? extends Object> context, Map<String, ? extends Object> additionalFields,
                                                             String prefix, String suffix) {
        Map<String, Object> paramMap = new HashMap<>();
        for (Map.Entry<String, ? extends Object> entry : context.entrySet()) {
            String parameterName = entry.getKey();
            if (parameterName.startsWith(prefix)) {
                if (UtilValidate.isNotEmpty(suffix)) {
                    if (parameterName.endsWith(suffix)) {
                        String key = parameterName.substring(prefix.length(), parameterName.length() - (suffix.length()));
                        if (entry.getValue() instanceof ByteBuffer) {
                            ByteBuffer value = (ByteBuffer) entry.getValue();
                            paramMap.put(key, value);
                        } else {
                            String value = (String) entry.getValue();
                            paramMap.put(key, value);
                        }
                    }
                } else {
                    String key = parameterName.substring(prefix.length());
                    if (context.get(parameterName) instanceof ByteBuffer) {
                        ByteBuffer value = (ByteBuffer) entry.getValue();
                        paramMap.put(key, value);
                    } else {
                        String value = (String) entry.getValue();
                        paramMap.put(key, value);
                    }
                }
            }
        }
        if (additionalFields != null) {
            for (Map.Entry<String, ? extends Object> entry : additionalFields.entrySet()) {
                String fieldName = entry.getKey();
                if (fieldName.startsWith(prefix)) {
                    if (UtilValidate.isNotEmpty(suffix)) {
                        if (fieldName.endsWith(suffix)) {
                            String key = fieldName.substring(prefix.length(), fieldName.length() - (suffix.length() - 1));
                            Object value = entry.getValue();
                            paramMap.put(key, value);

                            // check for image upload data
                            if (!(value instanceof String)) {
                                String nameKey = "_" + key + "_fileName";
                                Object nameVal = additionalFields.get("_" + fieldName + "_fileName");
                                if (nameVal != null) {
                                    paramMap.put(nameKey, nameVal);
                                }

                                String typeKey = "_" + key + "_contentType";
                                Object typeVal = additionalFields.get("_" + fieldName + "_contentType");
                                if (typeVal != null) {
                                    paramMap.put(typeKey, typeVal);
                                }

                                String sizeKey = "_" + key + "_size";
                                Object sizeVal = additionalFields.get("_" + fieldName + "_size");
                                if (sizeVal != null) {
                                    paramMap.put(sizeKey, sizeVal);
                                }
                            }
                        }
                    } else {
                        String key = fieldName.substring(prefix.length());
                        Object value = entry.getValue();
                        paramMap.put(key, value);

                        // check for image upload data
                        if (!(value instanceof String)) {
                            String nameKey = "_" + key + "_fileName";
                            Object nameVal = additionalFields.get("_" + fieldName + "_fileName");
                            if (nameVal != null) {
                                paramMap.put(nameKey, nameVal);
                            }

                            String typeKey = "_" + key + "_contentType";
                            Object typeVal = additionalFields.get("_" + fieldName + "_contentType");
                            if (typeVal != null) {
                                paramMap.put(typeKey, typeVal);
                            }

                            String sizeKey = "_" + key + "_size";
                            Object sizeVal = additionalFields.get("_" + fieldName + "_size");
                            if (sizeVal != null) {
                                paramMap.put(sizeKey, sizeVal);
                            }
                        }
                    }
                }
            }
        }
        return paramMap;
    }

    /**
     * Constructs a list of parameter values whose keys are matching a given prefix and suffix.
     * @param request the HTTP request containing the parameters
     * @param suffix  the suffix that must be matched which can be {@code null}
     * @param prefix  the prefix that must be matched which can be {@code null}
     * @return the list of parameter values whose keys are matching {@code prefix} and {@code suffix}.
     * @throws NullPointerException when {@code request} is {@code null}.
     */
    public static List<Object> makeParamListWithSuffix(HttpServletRequest request, String suffix, String prefix) {
        return makeParamListWithSuffix(request, Collections.emptyMap(), suffix, prefix);
    }

    /**
     * Constructs a list of parameter values whose keys are matching a given prefix and suffix.
     * @param request          the HTTP request containing the parameters
     * @param additionalFields the additional parameters
     * @param suffix           the suffix that must be matched which can be {@code null}
     * @param prefix           the prefix that must be matched which can be {@code null}
     * @return the list of parameter values whose keys are matching {@code prefix} and {@code suffix}.
     * @throws NullPointerException when {@code request} or {@code additionalFields} are {@code null}.
     */
    public static List<Object> makeParamListWithSuffix(HttpServletRequest request, Map<String, ?> additionalFields,
                                                       String suffix, String prefix) {
        Objects.requireNonNull(request);
        Objects.requireNonNull(additionalFields);
        Predicate<Map.Entry<String, ?>> pred = UtilValidate.isEmpty(prefix)
                ? e -> e.getKey().endsWith(suffix)
                : e -> e.getKey().endsWith(suffix) && e.getKey().startsWith(prefix);

        Stream<Object> params = request.getParameterMap().entrySet().stream()
                .filter(pred)
                .map(e -> e.getValue()[0]);

        Stream<Object> additionalParams = additionalFields.entrySet().stream()
                .filter(pred)
                .map(Map.Entry::getValue);

        return Stream.concat(params, additionalParams).collect(Collectors.toList());
    }

    /**
     * Given a request, returns the application name or "root" if deployed on root
     * @param request An HttpServletRequest to get the name info from
     * @return String
     */
    public static String getApplicationName(HttpServletRequest request) {
        String appName = "root";
        if (request.getContextPath().length() > 1) {
            appName = request.getContextPath().substring(1);
        }
        // When you set a mountpoint which contains a slash inside its name (ie not only a slash as a trailer, which is possible),
        // as it's needed with OFBIZ-10765, OFBiz tries to create a cookie with a slash in its name and that's impossible.
        return appName.replace("/", "_");
    }

    public static void setInitialRequestInfo(HttpServletRequest request) {
        HttpSession session = request.getSession();
        if (UtilValidate.isNotEmpty(session.getAttribute("_WEBAPP_NAME_"))) {
            // oops, info already in place...
            return;
        }

        String fullRequestUrl = getFullRequestUrl(request);

        session.setAttribute("_WEBAPP_NAME_", getApplicationName(request));
        session.setAttribute("_CLIENT_LOCALE_", request.getLocale());
        session.setAttribute("_CLIENT_REQUEST_", fullRequestUrl);
        session.setAttribute("_CLIENT_USER_AGENT_", request.getHeader("User-Agent") != null ? request.getHeader("User-Agent") : "");
        session.setAttribute("_CLIENT_REFERER_", request.getHeader("Referer") != null ? request.getHeader("Referer") : "");

        session.setAttribute("_CLIENT_FORWARDED_FOR_", request.getHeader("X-Forwarded-For"));
        session.setAttribute("_CLIENT_REMOTE_ADDR_", request.getRemoteAddr());
        session.setAttribute("_CLIENT_REMOTE_HOST_", request.getRemoteHost());
        session.setAttribute("_CLIENT_REMOTE_USER_", request.getRemoteUser());
    }

    private static StringBuilder prepareServerRootUrl(HttpServletRequest request) {
        StringBuilder requestUrl = new StringBuilder();
        requestUrl.append(request.getScheme());
        requestUrl.append("://" + request.getServerName());
        if (request.getServerPort() != 80 && request.getServerPort() != 443) {
            requestUrl.append(":" + request.getServerPort());
        }
        return requestUrl;
    }

    public static String getServerRootUrl(HttpServletRequest request) {
        return prepareServerRootUrl(request).toString();
    }

    public static String getFullRequestUrl(HttpServletRequest request) {
        StringBuilder requestUrl = prepareServerRootUrl(request);
        requestUrl.append(request.getRequestURI());
        if (request.getQueryString() != null) {
            requestUrl.append("?" + request.getQueryString());
        }
        return requestUrl.toString();
    }

    /**
     * Resolve the method send with the request.
     * check first the parameter _method before return the request method
     * @param request
     * @return method
     */
    public static String getRequestMethod(HttpServletRequest request) {
        return request.getParameter("_method") != null
                ? request.getParameter("_method") : request.getMethod();
    }

    public static Locale getLocale(HttpServletRequest request, HttpSession session, Object appDefaultLocale) {
        // check session first, should override all if anything set there
        Object localeObject = session != null ? session.getAttribute("locale") : null;

        // next see if the userLogin has a value
        if (localeObject == null) {
            Map<?, ?> userLogin = (Map<?, ?>) session.getAttribute("userLogin");
            if (userLogin == null) {
                userLogin = (Map<?, ?>) session.getAttribute("autoUserLogin");
            }

            if (userLogin != null) {
                localeObject = userLogin.get("lastLocale");
            }
        }

        // no user locale? before global default try appDefaultLocale if specified
        if (localeObject == null && UtilValidate.isNotEmpty(appDefaultLocale)) {
            localeObject = appDefaultLocale;
        }

        // finally request (w/ a fall back to default)
        if (localeObject == null) {
            localeObject = request != null ? request.getLocale() : null;
        }

        return UtilMisc.ensureLocale(localeObject);
    }

    /**
     * Get the Locale object from a session variable; if not found use the browser's default
     * @param request HttpServletRequest object to use for lookup
     * @return Locale The current Locale to use
     */
    public static Locale getLocale(HttpServletRequest request) {
        if (request == null) {
            return Locale.getDefault();
        }
        return getLocale(request, request.getSession(), null);
    }

    /**
     * Get the Locale object from a session variable; if not found use the system's default.
     * NOTE: This method is not recommended because it ignores the Locale from the browser not having the request object.
     * @param session HttpSession object to use for lookup
     * @return Locale The current Locale to use
     */
    public static Locale getLocale(HttpSession session) {
        if (session == null) {
            return Locale.getDefault();
        }
        return getLocale(null, session, null);
    }

    public static void setLocale(HttpServletRequest request, String localeString) {
        setLocale(request.getSession(), UtilMisc.parseLocale(localeString));
    }

    public static void setLocale(HttpSession session, Locale locale) {
        session.setAttribute("locale", locale);
    }

    public static void setLocaleIfNone(HttpSession session, String localeString) {
        if (UtilValidate.isNotEmpty(localeString) && session.getAttribute("locale") == null) {
            setLocale(session, UtilMisc.parseLocale(localeString));
        }
    }

    public static void setTimeZone(HttpServletRequest request, String tzId) {
        setTimeZone(request.getSession(), UtilDateTime.toTimeZone(tzId));
    }

    public static void setTimeZone(HttpSession session, TimeZone timeZone) {
        session.setAttribute(SESSION_KEY_TIMEZONE, timeZone);
    }

    public static void setTimeZoneIfNone(HttpSession session, String timeZoneString) {
        if (UtilValidate.isNotEmpty(timeZoneString) && session.getAttribute(SESSION_KEY_TIMEZONE) == null) {
            UtilHttp.setTimeZone(session, UtilDateTime.toTimeZone(timeZoneString));
        }
    }

    public static TimeZone getTimeZone(HttpServletRequest request) {
        HttpSession session = request.getSession();
        TimeZone timeZone = (TimeZone) session.getAttribute(SESSION_KEY_TIMEZONE);
        Map<String, String> userLogin = UtilGenerics.cast(session.getAttribute("userLogin"));
        if (userLogin != null) {
            String tzId = userLogin.get("lastTimeZone");
            if (tzId != null) {
                timeZone = TimeZone.getTimeZone(tzId);
            }
        }
        if (timeZone == null) {
            timeZone = TimeZone.getDefault();
        }
        session.setAttribute(SESSION_KEY_TIMEZONE, timeZone);
        return timeZone;
    }

    public static TimeZone getTimeZone(HttpServletRequest request, HttpSession session, String appDefaultTimeZoneString) {
        // check session first, should override all if anything set there
        TimeZone timeZone = session != null ? (TimeZone) session.getAttribute(SESSION_KEY_TIMEZONE) : null;

        // next see if the userLogin has a value
        if (timeZone == null) {
            Map<String, Object> userLogin = UtilGenerics.checkMap(session.getAttribute("userLogin"), String.class, Object.class);
            if (userLogin == null) {
                userLogin = UtilGenerics.checkMap(session.getAttribute("autoUserLogin"), String.class, Object.class);
            }

            if ((userLogin != null) && (UtilValidate.isNotEmpty(userLogin.get("lastTimeZone")))) {
                timeZone = UtilDateTime.toTimeZone((String) userLogin.get("lastTimeZone"));
            }
        }

        // if there is no user TimeZone, we will got the application default time zone (if provided)
        if ((timeZone == null) && (UtilValidate.isNotEmpty(appDefaultTimeZoneString))) {
            timeZone = UtilDateTime.toTimeZone(appDefaultTimeZoneString);
        }

        // finally request (w/ a fall back to default)
        if (timeZone == null) {
            timeZone = TimeZone.getDefault();
        }

        return timeZone;
    }

    /**
     * Return the VisualTheme object from the user session
     * @param request
     * @return VisualTheme
     */
    public static VisualTheme getVisualTheme(HttpServletRequest request) {
        return (VisualTheme) request.getSession().getAttribute(SESSION_KEY_THEME);
    }

    public static void setVisualTheme(HttpServletRequest request, VisualTheme visualTheme) {
        setVisualTheme(request.getSession(), visualTheme);
    }

    public static void setVisualTheme(HttpSession session, VisualTheme visualTheme) {
        session.setAttribute(SESSION_KEY_THEME, visualTheme);
    }

    /**
     * Get the currency string from the session.
     * @param session HttpSession object to use for lookup
     * @return String The ISO currency code
     */
    public static String getCurrencyUom(HttpSession session, String appDefaultCurrencyUom) {
        // session, should override all if set there
        String iso = (String) session.getAttribute("currencyUom");

        // check userLogin next, ie if nothing to override in the session
        if (iso == null) {
            Map<String, ?> userLogin = UtilGenerics.cast(session.getAttribute("userLogin"));
            if (userLogin == null) {
                userLogin = UtilGenerics.cast(session.getAttribute("autoUserLogin"));
            }

            if (userLogin != null) {
                iso = (String) userLogin.get("lastCurrencyUom");
            }
        }

        // no user currency? before global default try appDefaultCurrencyUom if specified
        if (iso == null && UtilValidate.isNotEmpty(appDefaultCurrencyUom)) {
            iso = appDefaultCurrencyUom;
        }

        // if none is set we will use the configured default
        if (iso == null) {
            try {
                iso = UtilProperties.getPropertyValue("general", "currency.uom.id.default", "USD");
            } catch (Exception e) {
                Debug.logWarning("Error getting the general:currency.uom.id.default value: " + e.toString(), MODULE);
            }
        }


        // if still none we will use the default for whatever currency we can get...
        if (iso == null) {
            Currency cur = Currency.getInstance(getLocale(session));
            iso = cur.getCurrencyCode();
        }

        return iso;
    }

    /**
     * Get the currency string from the session.
     * @param request HttpServletRequest object to use for lookup
     * @return String The ISO currency code
     */
    public static String getCurrencyUom(HttpServletRequest request) {
        return getCurrencyUom(request.getSession(), null);
    }

    /**
     * Simple event to set the users per-session currency uom value
     */
    public static void setCurrencyUom(HttpSession session, String currencyUom) {
        session.setAttribute("currencyUom", currencyUom);
    }

    public static void setCurrencyUomIfNone(HttpSession session, String currencyUom) {
        if (UtilValidate.isNotEmpty(currencyUom) && session.getAttribute("currencyUom") == null) {
            session.setAttribute("currencyUom", currencyUom);
        }
    }

    /**
     * URL Encodes a Map of arguments
     */
    public static String urlEncodeArgs(Map<String, ? extends Object> args) {
        return urlEncodeArgs(args, true);
    }

    /**
     * URL Encodes a Map of arguments
     */
    public static String urlEncodeArgs(Map<String, ? extends Object> args, boolean useExpandedEntites) {
        return urlEncodeArgs(args, useExpandedEntites, false);
    }

    /**
     * URL Encodes a Map of arguments
     */
    public static String urlEncodeArgs(Map<String, ? extends Object> args, boolean useExpandedEntites, boolean preserveEmpty) {
        StringBuilder buf = new StringBuilder();
        if (args != null) {
            for (Map.Entry<String, ? extends Object> entry : args.entrySet()) {
                String name = entry.getKey();
                Object value = entry.getValue();
                if (preserveEmpty && value == null) {
                    value = "";
                }
                if (name == null || value == null) {
                    continue;
                }

                Collection<?> col;
                if (value instanceof String) {
                    col = Arrays.asList(value);
                } else if (value instanceof Collection) {
                    col = UtilGenerics.cast(value);
                } else if (value.getClass().isArray()) {
                    col = Arrays.asList((Object[]) value);
                } else {
                    col = Arrays.asList(value);
                }

                String valueStr = null;
                for (Object colValue : col) {
                    if (colValue instanceof String) {
                        valueStr = (String) colValue;
                    } else if (colValue == null) {
                        continue;
                    } else {
                        valueStr = colValue.toString();
                    }

                    if (UtilValidate.isNotEmpty(valueStr) || preserveEmpty) {
                        if (buf.length() > 0) {
                            if (useExpandedEntites) {
                                buf.append("&amp;");
                            } else {
                                buf.append("&");
                            }
                        }
                        buf.append(UtilCodec.getEncoder("url").encode(name));
                        buf.append('=');
                        buf.append(UtilCodec.getEncoder("url").encode(valueStr));
                    }
                }
            }
        }
        return buf.toString();
    }

    /**
     * Encodes a query parameter
     * @throws UnsupportedEncodingException
     */
    public static String getEncodedParameter(String parameter) throws UnsupportedEncodingException {
        return URLEncoder.encode(parameter, "UTF-8");
    }

    public static String getRequestUriFromTarget(String target) {
        if (UtilValidate.isEmpty(target)) {
            return null;
        }
        int endOfRequestUri = target.length();
        if (target.indexOf('?') > 0) {
            endOfRequestUri = target.indexOf('?');
        }
        int slashBeforeRequestUri = target.lastIndexOf('/', endOfRequestUri);
        String requestUri = null;
        if (slashBeforeRequestUri < 0) {
            requestUri = target.substring(0, endOfRequestUri);
        } else {
            requestUri = target.substring(slashBeforeRequestUri, endOfRequestUri);
        }
        return requestUri;
    }

    /**
     * Returns the query string contained in a request target - basically everything
     * after and including the ? character.
     * @param target The request target
     * @return The query string
     */
    public static String getQueryStringFromTarget(String target) {
        if (UtilValidate.isEmpty(target)) {
            return "";
        }
        int queryStart = target.indexOf('?');
        if (queryStart != -1) {
            return target.substring(queryStart);
        }
        return "";
    }

    /**
     * Removes the query string from a request target - basically everything
     * after and including the ? character.
     * @param target The request target
     * @return The request target string
     */
    public static String removeQueryStringFromTarget(String target) {
        if (UtilValidate.isEmpty(target)) {
            return null;
        }
        int queryStart = target.indexOf('?');
        if (queryStart < 0) {
            return target;
        }
        return target.substring(0, queryStart);
    }

    public static String getWebappMountPointFromTarget(String target) {
        int firstChar = 0;
        if (UtilValidate.isEmpty(target)) {
            return null;
        }
        if (target.charAt(0) == '/') {
            firstChar = 1;
        }
        int pathSep = target.indexOf('/', 1);
        String webappMountPoint = null;
        if (pathSep > 0) {
            // if not then no good, supposed to be a inter-app, but there is no path sep! will do general search with null and treat like an intra-app
            webappMountPoint = target.substring(firstChar, pathSep);
        }
        return webappMountPoint;
    }

    public static String encodeAmpersands(String htmlString) {
        StringBuilder htmlBuffer = new StringBuilder(htmlString);
        int ampLoc = -1;
        while ((ampLoc = htmlBuffer.indexOf("&", ampLoc + 1)) != -1) {
            //NOTE: this should work fine, but if it doesn't could try making sure all characters between & and ; are letters, that would qualify
            // as an entity

            // found ampersand, is it already and entity? if not change it to &amp;
            int semiLoc = htmlBuffer.indexOf(";", ampLoc);
            if (semiLoc != -1) {
                // found a semi colon, if it has another & or an = before it, don't count it as an entity, otherwise it may be an entity, so skip it
                int eqLoc = htmlBuffer.indexOf("=", ampLoc);
                int amp2Loc = htmlBuffer.indexOf("&", ampLoc + 1);
                if ((eqLoc == -1 || eqLoc > semiLoc) && (amp2Loc == -1 || amp2Loc > semiLoc)) {
                    continue;
                }
            }

            // at this point not an entity, no substitute with a &amp;
            htmlBuffer.insert(ampLoc + 1, "amp;");
        }
        return htmlBuffer.toString();
    }

    public static String encodeBlanks(String htmlString) {
        return htmlString.replace(" ", "%20");
    }

    public static String setResponseBrowserProxyNoCache(HttpServletRequest request, HttpServletResponse response) {
        setResponseBrowserProxyNoCache(response);
        return "success";
    }

    public static void setResponseBrowserProxyNoCache(HttpServletResponse response) {
        long nowMillis = System.currentTimeMillis();
        response.setDateHeader("Expires", nowMillis);
        response.setDateHeader("Last-Modified", nowMillis); // always modified
        response.setHeader("Cache-Control", "no-store, no-cache, must-revalidate, private"); // HTTP/1.1
        response.setHeader("Pragma", "no-cache"); // HTTP/1.0
    }

    public static void setResponseBrowserDefaultSecurityHeaders(HttpServletResponse resp, ConfigXMLReader.ViewMap viewMap) {
        // See https://cwiki.apache.org/confluence/display/OFBIZ/How+to+Secure+HTTP+Headers for details and how to test
        String xFrameOption = null;
        // HTTP Strict-Transport-Security (HSTS) enforces secure (HTTP over SSL/TLS) connections to the server.
        String strictTransportSecurity = null;
        if (viewMap != null) {
            xFrameOption = viewMap.getxFrameOption();
            strictTransportSecurity = viewMap.getStrictTransportSecurity();
        }
        // Default to sameorigin
        if (UtilValidate.isNotEmpty(xFrameOption)) {
            if (!"none".equals(xFrameOption)) {
                resp.addHeader("x-frame-options", xFrameOption);
            }
        } else {
            resp.addHeader("x-frame-options", "sameorigin");
        }

        // Default to "max-age=31536000; includeSubDomains" 31536000 secs = 1 year
        if (UtilValidate.isNotEmpty(strictTransportSecurity)) {
            if (!"none".equals(strictTransportSecurity)) {
                resp.addHeader("strict-transport-security", strictTransportSecurity);
            }
        } else {
            if (EntityUtilProperties.getPropertyAsBoolean("requestHandler", "strict-transport-security", true)) { // FIXME later pass req
                // .getAttribute("delegator") as last argument
                resp.addHeader("strict-transport-security", "max-age=31536000; includeSubDomains");
            }
        }

        /** The only x-content-type-options defined value, "nosniff", prevents Internet Explorer from MIME-sniffing a response away from the
         * declared content-type.
         This also applies to Google Chrome, when downloading extensions. */
        resp.addHeader("x-content-type-options", "nosniff");

        /** This header enables the Cross-site scripting (XSS) filter built into most recent web browsers.
         It's usually enabled by default anyway, so the role of this header is to re-enable the filter for this particular website if it was
         disabled by the user.
         This header is supported in IE 8+, and in Chrome (not sure which versions). The anti-XSS filter was added in Chrome 4. Its unknown if that
         version honored this header.
         FireFox has still an open bug entry and "offers" only the noscript plugin
         https://wiki.mozilla.org/Security/Features/XSS_Filter
         https://bugzilla.mozilla.org/show_bug.cgi?id=528661
         **/
        resp.addHeader("X-XSS-Protection", "1; mode=block");
        resp.setHeader("Referrer-Policy", "no-referrer-when-downgrade"); // This is the default (in Firefox at least)

        if (EntityUtilProperties.getPropertyAsBoolean("security", "useContent-Security-Policy", true)) {
            String contentSecurityPolicy = EntityUtilProperties.getPropertyValueFromDelegatorName(
                    "security", "Content-Security-Policy", "Content-Security-Policy-Report-Only", "default");
            String policyDirectives = EntityUtilProperties.getPropertyValueFromDelegatorName(
                    "security", "PolicyDirectives", "default-src 'self'", "default");
            resp.setHeader(contentSecurityPolicy, policyDirectives);
        }
        SameSiteFilter.addSameSiteCookieAttribute(resp);
        // TODO in custom project. Public-Key-Pins-Report-Only is interesting but can't be used OOTB because of demos (the letsencrypt certificate
        // is renewed every 3 months)
    }


    public static String getContentTypeByFileName(String fileName) {
        FileNameMap mime = URLConnection.getFileNameMap();
        return mime.getContentTypeFor(fileName);
    }

    /**
     * Stream an array of bytes to the browser
     * This method will close the ServletOutputStream when finished
     * @param response    HttpServletResponse object to get OutputStream from
     * @param bytes       Byte array of content to stream
     * @param contentType The content type to pass to the browser
     * @param fileName    the fileName to tell the browser we are downloading
     * @throws IOException
     */
    public static void streamContentToBrowser(HttpServletResponse response, byte[] bytes, String contentType, String fileName) throws IOException {
        // tell the browser not the cache
        setResponseBrowserProxyNoCache(response);

        // set the response info
        response.setContentLength(bytes.length);
        if (contentType != null) {
            response.setContentType(contentType);
        }
        if (fileName != null) {
            setContentDisposition(response, fileName);
        }

        // create the streams

        // stream the content
        try (OutputStream out = response.getOutputStream();
                InputStream in = new ByteArrayInputStream(bytes)) {
            streamContent(out, in, bytes.length);
            out.flush();
        } catch (IOException e) {
            throw e;
        }
    }

    public static void streamContentToBrowser(HttpServletResponse response, byte[] bytes, String contentType) throws IOException {
        streamContentToBrowser(response, bytes, contentType, null);
    }

    /**
     * Streams content from InputStream to the ServletOutputStream
     * This method will close the ServletOutputStream when finished
     * This method does not close the InputSteam passed
     * @param response    HttpServletResponse object to get OutputStream from
     * @param in          InputStream of the actual content
     * @param length      Size (in bytes) of the content
     * @param contentType The content type to pass to the browser
     * @throws IOException
     */
    public static void streamContentToBrowser(HttpServletResponse response, InputStream in, int length, String contentType, String fileName)
            throws IOException {
        // tell the browser not the cache
        setResponseBrowserProxyNoCache(response);

        // set the response info
        response.setContentLength(length);
        if (contentType != null) {
            response.setContentType(contentType);
        }
        if (fileName != null) {
            setContentDisposition(response, fileName);
        }

        // stream the content
        try (OutputStream out = response.getOutputStream()) {
            streamContent(out, in, length);
            out.flush();
        } catch (IOException e) {
            throw e;
        }
    }

    public static void streamContentToBrowser(HttpServletResponse response, InputStream in, int length, String contentType) throws IOException {
        streamContentToBrowser(response, in, length, contentType, null);
    }

    /**
     * Stream binary content from InputStream to OutputStream
     * This method does not close the streams passed
     * @param out    OutputStream content should go to
     * @param in     InputStream of the actual content
     * @param length Size (in bytes) of the content
     * @throws IOException
     */
    private static void streamContent(OutputStream out, InputStream in, int length) throws IOException {
        // make sure we have something to write to
        if (out == null) {
            throw new IOException("Attempt to write to null output stream");
        }

        // make sure we have something to read from
        if (in == null) {
            throw new IOException("Attempt to read from null input stream");
        }

        // make sure we have some content
        if (length == 0) {
            throw new IOException("Attempt to write 0 bytes of content to output stream");
        }

        // initialize the buffered streams
        int bufferSize = EntityUtilProperties.getPropertyAsInteger("content", "stream.buffersize", 8192);
        byte[] buffer = new byte[bufferSize];
        int read = 0;
        try (BufferedOutputStream bos = new BufferedOutputStream(out, bufferSize);
                 BufferedInputStream bis = new BufferedInputStream(in, bufferSize)) {
            while ((read = bis.read(buffer, 0, buffer.length)) != -1) {
                bos.write(buffer, 0, read);
            }
        } catch (IOException e) {
            Debug.logError(e, "Problem reading/writing buffers", MODULE);
            throw e;
        }
    }

    public static String stripViewParamsFromQueryString(String queryString) {
        return stripViewParamsFromQueryString(queryString, null);
    }

    public static String stripViewParamsFromQueryString(String queryString, String paginatorNumber) {
        Set<String> paramNames = new HashSet<>();
        if (UtilValidate.isNotEmpty(paginatorNumber)) {
            paginatorNumber = "_" + paginatorNumber;
        }
        paramNames.add("VIEW_INDEX" + paginatorNumber);
        paramNames.add("VIEW_SIZE" + paginatorNumber);
        paramNames.add("viewIndex" + paginatorNumber);
        paramNames.add("viewSize" + paginatorNumber);
        return stripNamedParamsFromQueryString(queryString, paramNames);
    }

    public static String stripNamedParamsFromQueryString(String queryString, Collection<String> paramNames) {
        String retStr = null;
        if (UtilValidate.isNotEmpty(queryString)) {
            StringTokenizer queryTokens = new StringTokenizer(queryString, "&");
            StringBuilder cleanQuery = new StringBuilder();
            while (queryTokens.hasMoreTokens()) {
                String token = queryTokens.nextToken();
                if (token.startsWith("amp;")) {
                    token = token.substring(4);
                }
                int equalsIndex = token.indexOf("=");
                String name = token;
                if (equalsIndex > 0) {
                    name = token.substring(0, equalsIndex);
                }
                if (!paramNames.contains(name)) {
                    if (cleanQuery.length() > 0) {
                        cleanQuery.append("&");
                    }
                    cleanQuery.append(token);
                }
            }
            retStr = cleanQuery.toString();
        }
        return retStr;
    }

    /**
     * Given multi form data with the ${param}_o_N notation, creates a Collection
     * of Maps for the submitted rows. Each Map contains the key/value pairs
     * of a particular row. The keys will be stripped of the _o_N suffix.
     * There is an additionaly key "row" for each Map that holds the
     * index of the row.
     */
    public static Collection<Map<String, Object>> parseMultiFormData(Map<String, Object> parameters) {
        Map<Integer, Map<String, Object>> rows = new HashMap<>(); // stores the rows keyed by row number

        // first loop through all the keys and create a hashmap for each ${ROW_SUBMIT_PREFIX}${N} = Y
        for (Map.Entry<String, Object> entry : parameters.entrySet()) {
            String key = entry.getKey();
            // skip everything that is not ${ROW_SUBMIT_PREFIX}N
            if (key == null || key.length() <= ROW_SUBMIT_PREFIX_LENGTH) {
                continue;
            }
            if (key.indexOf(MULTI_ROW_DELIMITER) <= 0) {
                continue;
            }
            if (!key.substring(0, ROW_SUBMIT_PREFIX_LENGTH).equals(ROW_SUBMIT_PREFIX)) {
                continue;
            }
            if (!"Y".equals(entry.getValue())) {
                continue;
            }

            // decode the value of N and create a new map for it
            Integer n = Integer.decode(key.substring(ROW_SUBMIT_PREFIX_LENGTH, key.length()));
            Map<String, Object> m = new HashMap<>();
            m.put("row", n); // special "row" = N tuple
            rows.put(n, m); // key it to N
        }

        // next put all parameters with matching N in the right map
        for (Map.Entry<String, Object> entry : parameters.entrySet()) {
            String key = entry.getKey();
            // skip keys without DELIMITER and skip ROW_SUBMIT_PREFIX
            if (key == null) {
                continue;
            }
            int index = key.indexOf(MULTI_ROW_DELIMITER);
            if (index <= 0) {
                continue;
            }
            if (key.length() > ROW_SUBMIT_PREFIX_LENGTH && key.substring(0, ROW_SUBMIT_PREFIX_LENGTH).equals(ROW_SUBMIT_PREFIX)) {
                continue;
            }

            // get the map with index N
            Integer n = Integer.decode(key.substring(index + MULTI_ROW_DELIMITER_LENGTH, key.length())); // N from ${param}${DELIMITER}${N}
            Map<String, Object> map = rows.get(n);
            if (map == null) {
                continue;
            }

            // get the key without the <DELIMITER>N suffix and store it and its value
            String newKey = key.substring(0, index);
            map.put(newKey, entry.getValue());
        }
        // return only the values, which is the list of maps
        return rows.values();
    }

    /**
     * Returns a new map containing all the parameters from the input map except for the
     * multi form parameters (usually named according to the ${param}_o_N notation).
     */
    public static <V> Map<String, V> removeMultiFormParameters(Map<String, V> parameters) {
        Map<String, V> filteredParameters = new HashMap<>();
        for (Map.Entry<String, V> entry : parameters.entrySet()) {
            String key = entry.getKey();
            if (key != null && (key.indexOf(MULTI_ROW_DELIMITER) != -1 || key.indexOf("_useRowSubmit") != -1 || key.indexOf("_rowCount") != -1)) {
                continue;
            }

            filteredParameters.put(key, entry.getValue());
        }
        return filteredParameters;
    }

    /**
     * Utility to make a composite parameter from the given prefix and suffix.
     * The prefix should be a regular parameter name such as meetingDate. The
     * suffix is the composite field, such as the hour of the meeting. The
     * result would be meetingDate_${COMPOSITE_DELIMITER}_hour.
     * @param prefix
     * @param suffix
     * @return the composite parameter
     */
    public static String makeCompositeParam(String prefix, String suffix) {
        return prefix + COMPOSITE_DELIMITER + suffix;
    }

    /**
     * Assembles a composite object from a set of parameters identified by a common prefix.
     * <p>
     * For example, consider the following form widget field:
     * <pre>
     * {@code
     * <field name="meetingDate">
     *     <date-time type="timestamp" input-method="time-dropdown">
     * </field>
     * }
     * </pre>
     * The HTML result is three input boxes to input the date, hour and minutes separately.
     * The parameter names are named {@code meetingDate_c_date}, {@code meetingDate_c_hour},
     * {@code meetingDate_c_minutes}.  Additionally, there will be a field named {@code meetingDate_c_compositeType}
     * with a value of "Timestamp". where "_c_" is the {@link #COMPOSITE_DELIMITER}.  These parameters will then be
     * re-composed into a Timestamp object from the composite fields.
     * @param request the HTTP request containing the parameters
     * @param prefix  the string identifying the set of parameters that must be composed
     * @return a composite object from data or {@code null} if not supported or a parsing error occurred.
     */
    public static Object makeParamValueFromComposite(HttpServletRequest request, String prefix) {
        String compositeType = request.getParameter(makeCompositeParam(prefix, "compositeType"));
        if (UtilValidate.isEmpty(compositeType)) {
            return null;
        }
        // Collect the components.
        String prefixDelim = prefix + COMPOSITE_DELIMITER;
        Map<String, String> data = request.getParameterMap().entrySet().stream()
                .filter(e -> e.getKey().startsWith(prefixDelim))
                .collect(Collectors.toMap(
                        e -> e.getKey().substring(prefixDelim.length()),
                        e -> e.getValue()[0]));

        if (Debug.verboseOn()) {
            Debug.logVerbose("Creating composite type with parameter data: " + data.toString(), MODULE);
        }

        // Assemble the composite data from the components
        if ("Timestamp".equals(compositeType)) {
            String date = data.get("date");
            String hour = data.get("hour");
            String minutes = data.get("minutes");
            String ampm = data.get("ampm");
            if (date == null || date.length() < 10 || UtilValidate.isEmpty(hour) || UtilValidate.isEmpty(minutes)) {
                return null;
            }
            try {
                int h = Integer.parseInt(hour);
                Timestamp ts = Timestamp.valueOf(date.substring(0, 10) + " 00:00:00.000");
                if (UtilValidate.isNotEmpty(ampm)) {
                    boolean isAM = "AM".equals(ampm);
                    if (isAM && h == 12) {
                        h = 0;
                    } else if (!isAM && h < 12) {
                        h += 12;
                    }
                }
                LocalDateTime ldt = ts.toLocalDateTime().withHour(h).withMinute(Integer.parseInt(minutes));
                return Timestamp.valueOf(ldt);
            } catch (IllegalArgumentException e) {
                Debug.logWarning("User input for composite timestamp was invalid: " + e.getMessage(), MODULE);
                return null;
            }
        }

        // we don't support any other compositeTypes (yet)
        return null;
    }

    /**
     * Obtains the session ID from the request, or "unknown" if no session pressent.
     */
    public static String getSessionId(HttpServletRequest request) {
        HttpSession session = request.getSession();
        return (session == null ? "unknown" : session.getId());
    }

    /**
     * Returns true if the user has JavaScript enabled.
     * @param request
     * @return whether javascript is enabled
     */
    public static boolean isJavaScriptEnabled(HttpServletRequest request) {
        HttpSession session = request.getSession();
        Boolean javaScriptEnabled = (Boolean) session.getAttribute("javaScriptEnabled");
        return javaScriptEnabled != null ? javaScriptEnabled : false;
    }

    /**
     * Returns the number or rows submitted by a multi form.
     */
    public static int getMultiFormRowCount(HttpServletRequest request) {
        return getMultiFormRowCount(getParameterMap(request));
    }

    /**
     * Returns the number or rows submitted by a multi form.
     */
    public static int getMultiFormRowCount(Map<String, ?> requestMap) {
        // The number of multi form rows is computed selecting the maximum index
        int rowCount = 0;
        String maxRowIndex = "";
        int rowDelimiterLength = MULTI_ROW_DELIMITER.length();
        for (String parameterName : requestMap.keySet()) {
            int rowDelimiterIndex = (parameterName != null ? parameterName.indexOf(MULTI_ROW_DELIMITER) : -1);
            if (rowDelimiterIndex > 0) {
                String thisRowIndex = parameterName.substring(rowDelimiterIndex + rowDelimiterLength);
                if (thisRowIndex.indexOf("_") > -1) {
                    thisRowIndex = thisRowIndex.substring(0, thisRowIndex.indexOf("_"));
                }
                if (maxRowIndex.length() < thisRowIndex.length()) {
                    maxRowIndex = thisRowIndex;
                } else if (maxRowIndex.length() == thisRowIndex.length() && maxRowIndex.compareTo(thisRowIndex) < 0) {
                    maxRowIndex = thisRowIndex;
                }
            }
        }
        if (UtilValidate.isNotEmpty(maxRowIndex)) {
            try {
                rowCount = Integer.parseInt(maxRowIndex);
                rowCount++; // row indexes are zero based
            } catch (NumberFormatException e) {
                Debug.logWarning("Invalid value for row index found: " + maxRowIndex, MODULE);
            }
        }
        return rowCount;
    }

    public static String stashParameterMap(HttpServletRequest request) {
        HttpSession session = request.getSession();
        Map<String, Map<String, Object>> paramMapStore = UtilGenerics.cast(session.getAttribute("_PARAM_MAP_STORE_"));
        if (paramMapStore == null) {
            paramMapStore = new HashMap<>();
            session.setAttribute("_PARAM_MAP_STORE_", paramMapStore);
        }
        Map<String, Object> parameters = getParameterMap(request);
        String paramMapId = RandomStringUtils.randomAlphanumeric(10);
        paramMapStore.put(paramMapId, parameters);
        return paramMapId;
    }

    public static void restoreStashedParameterMap(HttpServletRequest request, String paramMapId) {
        HttpSession session = request.getSession();
        Map<String, Map<String, Object>> paramMapStore = UtilGenerics.cast(session.getAttribute("_PARAM_MAP_STORE_"));
        if (paramMapStore != null) {
            Map<String, Object> paramMap = paramMapStore.get(paramMapId);
            if (paramMap != null) {
                paramMapStore.remove(paramMapId);
                for (Map.Entry<String, Object> paramEntry : paramMap.entrySet()) {
                    if (request.getAttribute(paramEntry.getKey()) != null) {
                        Debug.logWarning("Skipped loading parameter [" + paramEntry.getKey() + "] because it would have overwritten a request "
                                + "attribute", MODULE);
                        continue;
                    }
                    request.setAttribute(paramEntry.getKey(), paramEntry.getValue());
                }
            }
        }
    }

    /**
     * Returns a unique Id for the current request
     * @param request An HttpServletRequest to get the name info from
     * @return String
     */
    public static String getNextUniqueId(HttpServletRequest request) {
        Integer uniqueIdNumber = (Integer) request.getAttribute("UNIQUE_ID");
        if (uniqueIdNumber == null) {
            uniqueIdNumber = 1;
        }

        request.setAttribute("UNIQUE_ID", uniqueIdNumber + 1);
        return "autoId_" + uniqueIdNumber;
    }

    private static void setContentDisposition(final HttpServletResponse response, final String filename) {
        String dispositionType = UtilProperties.getPropertyValue("requestHandler", "content-disposition-type", "attachment");
        response.setHeader("Content-Disposition", String.format("%s; filename=\"%s\"", dispositionType, filename));
    }

    public static CloseableHttpClient getAllowAllHttpClient() {
        return getAllowAllHttpClient("component://base/config/ofbizssl.jks", "changeit");
    }

    private static CloseableHttpClient getAllowAllHttpClient(String jksStoreFileName, String jksStorePassword) {
        try {
            // Trust own CA and all self-signed certs
            SSLContext sslContext = SSLContexts.custom()
                    .loadTrustMaterial(FileUtil.getFile(jksStoreFileName), jksStorePassword.toCharArray(),
                            new TrustSelfSignedStrategy())
                    .build();
            // No host name verifier
            SSLConnectionSocketFactory sslsf = new SSLConnectionSocketFactory(
                    sslContext,
                    NoopHostnameVerifier.INSTANCE);
            CloseableHttpClient httpClient = HttpClients.custom()
                    .setSSLSocketFactory(sslsf)
                    .build();
            return httpClient;
        } catch (RuntimeException e) {
            throw e;
        } catch (Exception e) {
            return HttpClients.createDefault();
        }
    }

    public static String getMultiRowDelimiter() {
        return MULTI_ROW_DELIMITER;
    }

    public static String getRowSubmitPrefix() {
        return ROW_SUBMIT_PREFIX;
    }

    // From https://stackoverflow.com/questions/1806017/extracting-urls-from-a-text-document-using-java-regular-expressions/1806161#answer-1806161
    // If you need more Internet top-level domains: https://en.wikipedia.org/wiki/List_of_Internet_top-level_domains
    public static List<String> extractUrls(String input) {
        List<String> result = new ArrayList<String>();

        Pattern pattern = Pattern.compile(
                "\\b(((ht|f)tp(s?)\\:\\/\\/|~\\/|\\/)|www.)"
                        + "(\\w+:\\w+@)?(([-\\w]+\\.)+([a-zA-Z]{2,}))(:[\\d]{1,5})?"
                        + "(((\\/([-\\w~!$+|.,=]|%[a-f\\d]{2})+)+|\\/)+|\\?|#)?"
                        + "((\\?([-\\w~!$+|.,*:]|%[a-f\\d{2}])+=?"
                        + "([-\\w~!$+|.,*:=]|%[a-f\\d]{2})*)"
                        + "(&(?:[-\\w~!$+|.,*:]|%[a-f\\d{2}])+=?"
                        + "([-\\w~!$+|.,*:=]|%[a-f\\d]{2})*)*)*"
                        + "(#([-\\w~!$+|.,*:=]|%[a-f\\d]{2})*)?\\b");

        List<String> allowedProtocols = getAllowedProtocols();
        for (String protocol : allowedProtocols) {
            if (input.contains(protocol)) {
                result.add(input);
            }
        }

        if (result.isEmpty()) {
            Matcher matcher = pattern.matcher(input);
            while (matcher.find()) {
                String candidate = matcher.group();
                if (UtilValidate.isValidUrl(candidate)) {
                    result.add(candidate);
                }
            }
        }

        return result;
    }

    private static List<String> getAllowedProtocols() {
        List<String> allowedProtocolList = new LinkedList<>();
        allowedProtocolList.add("component://");
        String allowedProtocols = UtilProperties.getPropertyValue("security", "allowedProtocols");
        if (UtilValidate.isNotEmpty(allowedProtocols)) {
            List<String> allowedProtocolsList = StringUtil.split(allowedProtocols, ",");
            for (String protocol : allowedProtocolsList) {
                allowedProtocolList.add(protocol);
            }
        }
        return allowedProtocolList;
    }

}
