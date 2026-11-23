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
package org.apache.ofbiz.base.location;

import java.net.MalformedURLException;
import java.net.URL;
import java.util.Collections;
import java.util.HashMap;
import java.util.Map;
import java.util.Map.Entry;
import java.util.Properties;

import org.apache.ofbiz.base.util.Debug;
import org.apache.ofbiz.base.util.UtilProperties;
import org.apache.ofbiz.base.util.UtilValidate;

/**
 * A special location resolver that uses Strings like URLs, but with more options.
 *
 */
public final class FlexibleLocation {

    private static final String MODULE = FlexibleLocation.class.getName();
    private static final Map<String, LocationResolver> LOCATION_RESOLVERS;

    static {
        Map<String, LocationResolver> resolverMap = new HashMap<>(8);
        LocationResolver standardUrlResolver = new StandardUrlLocationResolver();
        resolverMap.put("http", standardUrlResolver);
        resolverMap.put("https", standardUrlResolver);
        resolverMap.put("ftp", standardUrlResolver);
        resolverMap.put("jar", standardUrlResolver);
        resolverMap.put("file", standardUrlResolver);
        resolverMap.put("classpath", new ClasspathLocationResolver());
        resolverMap.put("ofbizhome", new OFBizHomeLocationResolver());
        resolverMap.put("component", new ComponentLocationResolver());
        try {
            /* Note that the file must be placed in framework/base/config -
             * because this class may be initialized before all components
             * are loaded.
             */
            Properties properties = UtilProperties.createProperties("locationresolvers.properties");
            if (properties != null) {
                ClassLoader classLoader = Thread.currentThread().getContextClassLoader();
                for (Entry<Object, Object> entry : properties.entrySet()) {
                    String locationType = (String) entry.getKey();
                    String locationResolverName = (String) entry.getValue();
                    Class<?> lClass = classLoader.loadClass(locationResolverName);
                    resolverMap.put(locationType, (LocationResolver) lClass.getDeclaredConstructor().newInstance());
                }
            }
        } catch (Throwable e) {
            Debug.logError(e, "Exception thrown while loading locationresolvers.properties", MODULE);
        }
        LOCATION_RESOLVERS = Collections.unmodifiableMap(resolverMap);
    }

    /**
     * Find the location type descriptor for the passed location String;
     *   generally is all text before the first ":" character.
     *   If no type descriptor is found, defaults to "classpath".
     */
    private static String getLocationType(String location) {
        int colonIndex = location.indexOf(":");
        if (colonIndex > 0) {
            return location.substring(0, colonIndex);
        } else {
            return "classpath";
        }
    }

    /**
     * Resolves the gives location into a URL object for use in various ways.
     * The general format of the location is like a URL: {locationType}://location/path/file.ext
     * Supports standard locationTypes like http, https, ftp, jar and file
     * Supports a classpath location type for when desired to be used like any other URL
     * Supports OFBiz specific location types like ofbizhome and component
     * Supports additional locationTypes specified in the locationresolvers.properties file
     * @param location The location String to parse and create a URL from
     * @return URL object corresponding to the location String passed in
     * @throws MalformedURLException
     */
    public static URL resolveLocation(String location) throws MalformedURLException {
        return resolveLocation(location, null);
    }

    public static URL resolveLocation(String location, ClassLoader loader) throws MalformedURLException {
        if (UtilValidate.isEmpty(location)) {
            return null;
        }
        String locationType = getLocationType(location);
        LocationResolver resolver = LOCATION_RESOLVERS.get(locationType);
        if (resolver != null) {
            if (loader != null && resolver instanceof ClasspathLocationResolver) {
                ClasspathLocationResolver cplResolver = (ClasspathLocationResolver) resolver;
                return cplResolver.resolveLocation(location, loader);
            } else {
                return resolver.resolveLocation(location);
            }
        } else {
            throw new MalformedURLException("Could not find a LocationResolver for the location type: " + locationType);
        }
    }

    static String stripLocationType(String location) {
        if (UtilValidate.isEmpty(location)) {
            return "";
        }
        StringBuilder strippedSoFar = new StringBuilder(location);
        // first take care of the colon and everything before it
        int colonIndex = strippedSoFar.indexOf(":");
        if (colonIndex == 0) {
            strippedSoFar.deleteCharAt(0);
        } else if (colonIndex > 0) {
            strippedSoFar.delete(0, colonIndex + 1);
        }
        // now remove any extra forward slashes, ie as long as the first two are forward slashes remove the first one
        while (strippedSoFar.charAt(0) == '/' && strippedSoFar.charAt(1) == '/') {
            strippedSoFar.deleteCharAt(0);
        }
        return strippedSoFar.toString();
    }

    private FlexibleLocation() { }
}
