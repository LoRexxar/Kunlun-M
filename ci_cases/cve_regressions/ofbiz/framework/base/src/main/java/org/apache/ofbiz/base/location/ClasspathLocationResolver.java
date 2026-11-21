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

import org.apache.ofbiz.base.util.UtilURL;

/**
 * A special location resolver that uses Strings like URLs, but with more options
 *
 */

public class ClasspathLocationResolver implements LocationResolver {
    @Override
    public URL resolveLocation(String location) throws MalformedURLException {
        return resolveLocation(location, null);
    }

    /**
     * Resolve location url.
     * @param location the location
     * @param loader the loader
     * @return the url
     * @throws MalformedURLException the malformed url exception
     */
    public URL resolveLocation(String location, ClassLoader loader) throws MalformedURLException {
        String baseLocation = FlexibleLocation.stripLocationType(location);
        // if there is a leading forward slash, remove it
        if (baseLocation.charAt(0) == '/') {
            baseLocation = baseLocation.substring(1);
        }
        return UtilURL.fromResource(baseLocation, loader);
    }
}
