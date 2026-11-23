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
package org.apache.ofbiz.widget.model;

import java.io.IOException;
import java.net.URL;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import javax.servlet.ServletContext;
import javax.servlet.http.HttpServletRequest;
import javax.xml.parsers.ParserConfigurationException;

import org.apache.ofbiz.base.location.FlexibleLocation;
import org.apache.ofbiz.base.util.Debug;
import org.apache.ofbiz.base.util.GeneralException;
import org.apache.ofbiz.base.util.UtilHttp;
import org.apache.ofbiz.base.util.UtilValidate;
import org.apache.ofbiz.base.util.UtilXml;
import org.apache.ofbiz.base.util.cache.UtilCache;
import org.apache.ofbiz.widget.renderer.ScreenStringRenderer;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.xml.sax.SAXException;


/**
 * Widget Library - Screen factory class
 */
public class ScreenFactory {

    private static final String MODULE = ScreenFactory.class.getName();

    public static final UtilCache<String, Map<String, ModelScreen>> SCREEN_LOCATION_CACHE =
            UtilCache.createUtilCache("widget.screen.locationResource", 0, 0, false);
    public static final UtilCache<String, Map<String, ModelScreen>> SCREEN_WEBAPP_CACHE =
            UtilCache.createUtilCache("widget.screen.webappResource", 0, 0, false);

    public static boolean isCombinedName(String combinedName) {
        int numSignIndex = combinedName.lastIndexOf("#");
        if (numSignIndex == -1) {
            return false;
        }
        if (numSignIndex + 1 >= combinedName.length()) {
            return false;
        }
        return true;
    }

    public static String getResourceNameFromCombined(String combinedName) {
        // split out the name on the last "#"
        int numSignIndex = combinedName.lastIndexOf("#");
        if (numSignIndex == -1) {
            throw new IllegalArgumentException("Error in screen location/name: no \"#\" found to separate the location from the name;"
                    + "correct example: component://product/screen/product/ProductScreens.xml#EditProduct");
        }
        if (numSignIndex + 1 >= combinedName.length()) {
            throw new IllegalArgumentException("Error in screen location/name: the \"#\" was at the end with no screen name after it;"
                    + "correct example: component://product/screen/product/ProductScreens.xml#EditProduct");
        }
        String resourceName = combinedName.substring(0, numSignIndex);
        return resourceName;
    }

    public static String getScreenNameFromCombined(String combinedName) {
        // split out the name on the last "#"
        int numSignIndex = combinedName.lastIndexOf("#");
        if (numSignIndex == -1) {
            throw new IllegalArgumentException("Error in screen location/name: no \"#\" found to separate the location from the name;"
                    + "correct example: component://product/screen/product/ProductScreens.xml#EditProduct");
        }
        if (numSignIndex + 1 >= combinedName.length()) {
            throw new IllegalArgumentException("Error in screen location/name: the \"#\" was at the end with no screen name after it;"
                    + "correct example: component://product/screen/product/ProductScreens.xml#EditProduct");
        }
        String screenName = combinedName.substring(numSignIndex + 1);
        return screenName;
    }

    public static ModelScreen getScreenFromLocation(String combinedName)
            throws IOException, SAXException, ParserConfigurationException {
        String resourceName = getResourceNameFromCombined(combinedName);
        String screenName = getScreenNameFromCombined(combinedName);
        return getScreenFromLocation(resourceName, screenName);
    }

    public static ModelScreen getScreenFromLocation(String resourceName, String screenName)
            throws IOException, SAXException, ParserConfigurationException {
        Map<String, ModelScreen> modelScreenMap = getScreensFromLocation(resourceName);
        ModelScreen modelScreen = modelScreenMap.get(screenName);
        if (modelScreen == null) {
            throw new IllegalArgumentException("Could not find screen with name [" + screenName + "] in class resource [" + resourceName + "]");
        }
        return modelScreen;
    }

    public static Map<String, ModelScreen> getScreensFromLocation(String resourceName)
            throws IOException, SAXException, ParserConfigurationException {
        Map<String, ModelScreen> modelScreenMap = SCREEN_LOCATION_CACHE.get(resourceName);
        if (modelScreenMap == null) {
            synchronized (ScreenFactory.class) {
                modelScreenMap = SCREEN_LOCATION_CACHE.get(resourceName);
                if (modelScreenMap == null) {
                    long startTime = System.currentTimeMillis();
                    URL screenFileUrl = null;
                    screenFileUrl = FlexibleLocation.resolveLocation(resourceName);
                    if (screenFileUrl == null || UtilValidate.isUrlInStringAndDoesNotStartByComponentProtocol(screenFileUrl.toString())) {
                        throw new IllegalArgumentException("Could not resolve location to URL: " + resourceName);
                    }
                    Document screenFileDoc = UtilXml.readXmlDocument(screenFileUrl, true, true);
                    modelScreenMap = readScreenDocument(screenFileDoc, resourceName);
                    SCREEN_LOCATION_CACHE.put(resourceName, modelScreenMap);
                    double totalSeconds = (System.currentTimeMillis() - startTime) / 1000.0;
                    Debug.logInfo("Got " + modelScreenMap.size() + " screens in " + totalSeconds + "s from: "
                            + screenFileUrl.toExternalForm(), MODULE);
                }
            }
        }

        if (modelScreenMap.isEmpty()) {
            throw new IllegalArgumentException("Could not find screen file with name [" + resourceName + "]");
        }
        return modelScreenMap;
    }

    public static ModelScreen getScreenFromWebappContext(String resourceName, String screenName, HttpServletRequest request)
            throws IOException, SAXException, ParserConfigurationException {
        String webappName = UtilHttp.getApplicationName(request);
        String cacheKey = webappName + "::" + resourceName;


        Map<String, ModelScreen> modelScreenMap = SCREEN_WEBAPP_CACHE.get(cacheKey);
        if (modelScreenMap == null) {
            synchronized (ScreenFactory.class) {
                modelScreenMap = SCREEN_WEBAPP_CACHE.get(cacheKey);
                if (modelScreenMap == null) {
                    ServletContext servletContext = request.getServletContext();

                    URL screenFileUrl = servletContext.getResource(resourceName);
                    Document screenFileDoc = UtilXml.readXmlDocument(screenFileUrl, true, true);
                    modelScreenMap = readScreenDocument(screenFileDoc, resourceName);
                    SCREEN_WEBAPP_CACHE.put(cacheKey, modelScreenMap);
                }
            }
        }

        ModelScreen modelScreen = modelScreenMap.get(screenName);
        if (modelScreen == null) {
            throw new IllegalArgumentException("Could not find screen with name [" + screenName + "] in webapp resource [" + resourceName
                    + "] in the webapp [" + webappName + "]");
        }
        return modelScreen;
    }

    public static Map<String, ModelScreen> readScreenDocument(Document screenFileDoc, String sourceLocation) {
        Map<String, ModelScreen> modelScreenMap = new HashMap<>();
        if (screenFileDoc != null) {
            // read document and construct ModelScreen for each screen element
            Element rootElement = screenFileDoc.getDocumentElement();
            if (!"screens".equalsIgnoreCase(rootElement.getTagName())) {
                rootElement = UtilXml.firstChildElement(rootElement, "screens");
            }
            List<? extends Element> screenElements = UtilXml.childElementList(rootElement, "screen");
            for (Element screenElement: screenElements) {
                ModelScreen modelScreen = new ModelScreen(screenElement, modelScreenMap, sourceLocation);
                modelScreenMap.put(modelScreen.getName(), modelScreen);
            }
        }
        return modelScreenMap;
    }

    public static void renderReferencedScreen(String name, String location, ModelScreenWidget parentWidget, Appendable writer,
                                              Map<String, Object> context, ScreenStringRenderer screenStringRenderer) throws GeneralException {
        // check to see if the name is a composite name separated by a #, if so split it up and get it by the full loc#name
        if (ScreenFactory.isCombinedName(name)) {
            String combinedName = name;
            location = ScreenFactory.getResourceNameFromCombined(combinedName);
            name = ScreenFactory.getScreenNameFromCombined(combinedName);
        }

        ModelScreen modelScreen = null;
        if (UtilValidate.isNotEmpty(location)) {
            try {
                modelScreen = ScreenFactory.getScreenFromLocation(location, name);
            } catch (IOException | SAXException | ParserConfigurationException e) {
                String errMsg = "Error rendering included screen named [" + name + "] at location [" + location + "]: " + e.toString();
                Debug.logError(e, errMsg, MODULE);
                throw new RuntimeException(errMsg);
            }
        } else {
            modelScreen = parentWidget.getModelScreen().getModelScreenMap().get(name);
            if (modelScreen == null) {
                throw new IllegalArgumentException("Could not find screen with name [" + name + "] in the same file as the screen with name ["
                        + parentWidget.getModelScreen().getName() + "]");
            }
        }
        modelScreen.renderScreenString(writer, context, screenStringRenderer);
    }
}
