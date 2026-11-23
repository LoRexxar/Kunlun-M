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

import java.io.File;
import java.net.MalformedURLException;
import java.net.URI;
import java.net.URISyntaxException;
import java.net.URL;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

/**
 * URL Utilities - Simple Class for flexibly working with properties files
 *
 */
public final class UtilURL {

    private static final String MODULE = UtilURL.class.getName();
    private static final Map<String, URL> URL_MAP = new ConcurrentHashMap<>();

    private UtilURL() { }

    public static <C> URL fromClass(Class<C> contextClass) {
        String resourceName = contextClass.getName();
        int dotIndex = resourceName.lastIndexOf('.');

        if (dotIndex != -1) {
            resourceName = resourceName.substring(0, dotIndex);
        }
        resourceName += ".properties";

        return fromResource(contextClass, resourceName);
    }

    /**
     * Returns a <code>URL</code> instance from a resource name. Returns
     * <code>null</code> if the resource is not found.
     * <p>This method uses various ways to locate the resource, and in all
     * cases it tests to see if the resource exists - so it
     * is very inefficient.</p>
     * @param resourceName
     * @return
     */
    public static URL fromResource(String resourceName) {
        return fromResource(resourceName, null);
    }

    public static <C> URL fromResource(Class<C> contextClass, String resourceName) {
        if (contextClass == null) {
            return fromResource(resourceName, null);
        }
        return fromResource(resourceName, contextClass.getClassLoader());
    }

    /**
     * Returns a <code>URL</code> instance from a resource name. Returns
     * <code>null</code> if the resource is not found.
     * <p>This method uses various ways to locate the resource, and in all
     * cases it tests to see if the resource exists - so it
     * is very inefficient.</p>
     * @param resourceName
     * @param loader
     * @return
     */
    public static URL fromResource(String resourceName, ClassLoader loader) {
        URL url = URL_MAP.get(resourceName);
        URI uri;
        if (url != null) {
            try {
                uri = new URI(url.toString());
                url = uri.toURL();
            } catch (IllegalArgumentException | URISyntaxException | MalformedURLException e) {
                Debug.logWarning(e, "Exception thrown while copying URL", MODULE);
            }
        }
        if (loader == null) {
            try {
                loader = Thread.currentThread().getContextClassLoader();
            } catch (SecurityException e) {
                // Huh? The new object will be created by the current thread, so how is this any different than the previous code?
                loader = UtilURL.class.getClassLoader();
            }
        }
        url = loader.getResource(resourceName);
        if (url != null) {
            URL_MAP.put(resourceName, url);
            return url;
        }
        url = ClassLoader.getSystemResource(resourceName);
        if (url != null) {
            URL_MAP.put(resourceName, url);
            return url;
        }
        url = fromFilename(resourceName);
        if (url != null) {
            URL_MAP.put(resourceName, url);
            return url;
        }
        url = fromOfbizHomePath(resourceName);
        if (url != null) {
            URL_MAP.put(resourceName, url);
            return url;
        }
        url = fromUrlString(resourceName);
        if (url != null) {
            URL_MAP.put(resourceName, url);
        }
        return url;
    }

    public static URL fromFilename(String filename) {
        if (filename == null) {
            return null;
        }
        File file = new File(filename);
        URL url = null;

        try {
            if (file.exists()) {
                url = file.toURI().toURL();
            }
        } catch (MalformedURLException e) {
            Debug.logError(e, "unable to retrieve URL for file: " + filename, MODULE);
        }
        return url;
    }

    public static URL fromUrlString(String urlString) {
        URL url = null;
        URI uri;
        try {
            uri = new URI(urlString);
            url = uri.toURL();
        } catch (IllegalArgumentException | URISyntaxException | MalformedURLException e) {
            // We purposely don't want to do anything here.
        }
        return url;
    }

    public static URL fromOfbizHomePath(String filename) {
        String ofbizHome = System.getProperty("ofbiz.home");
        if (ofbizHome == null) {
            Debug.logWarning("No ofbiz.home property set in environment", MODULE);
            return null;
        }
        String newFilename = ofbizHome;
        if (!newFilename.endsWith("/") && !filename.startsWith("/")) {
            newFilename = newFilename + "/";
        }
        newFilename = newFilename + filename;
        return fromFilename(newFilename);
    }

    public static String getOfbizHomeRelativeLocation(URL fileUrl) {
        String ofbizHome = System.getProperty("ofbiz.home");
        String path = fileUrl.getPath();
        if (path.startsWith(ofbizHome)) {
            // note: the +1 is to remove the leading slash
            path = path.substring(ofbizHome.length() + 1);
        }
        return path;
    }
}
