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

import java.io.File;
import java.net.MalformedURLException;
import java.net.URI;
import java.net.URISyntaxException;
import java.net.URL;

/**
 * A special location resolver that uses Strings like URLs, but with more options
 *
 */

public class OFBizHomeLocationResolver implements LocationResolver {

    public static final String ENV_NAME = "ofbiz.home";

    @Override
    public URL resolveLocation(String location) throws MalformedURLException {
        String propValue = System.getProperty(ENV_NAME);
        if (propValue == null) {
            String errMsg = "The Java environment (-Dxxx=yyy) variable with name " + ENV_NAME + " is not set, cannot resolve location.";
            throw new MalformedURLException(errMsg);
        }
        StringBuilder baseLocation = new StringBuilder(FlexibleLocation.stripLocationType(location));
        // if there is not a forward slash between the two, add it
        if (baseLocation.charAt(0) != '/' && propValue.charAt(propValue.length() - 1) != '/') {
            baseLocation.insert(0, '/');
        }
        baseLocation.insert(0, propValue);
        String fileLocation = baseLocation.toString();
        if (File.separatorChar != '/') {
            fileLocation = fileLocation.replace(File.separatorChar, '/');
        }
        if (!fileLocation.startsWith("/")) {
            fileLocation = "/".concat(fileLocation);
        }
        try {
            return new URI("file", null, fileLocation, null).toURL();
        } catch (URISyntaxException e) {
            throw new MalformedURLException(e.getMessage());
        }
    }
}
