/*
 * The contents of this file are subject to the terms of the Common Development and
 * Distribution License (the License). You may not use this file except in compliance with the
 * License.
 *
 * You can obtain a copy of the License at legal/CDDLv1.0.txt. See the License for the
 * specific language governing permission and limitations under the License.
 *
 * When distributing Covered Software, include this CDDL Header Notice in each file and include
 * the License file at legal/CDDLv1.0.txt. If applicable, add the following below the CDDL
 * Header, with the fields enclosed by brackets [] replaced by your own identifying
 * information: "Portions copyright [year] [name of copyright owner]".
 *
 * Copyright 2015-2016 ForgeRock AS.
 * Portions copyright 2023-2025 3A Systems LLC.
 */

package org.forgerock.openam.services.baseurl;

import jakarta.servlet.http.HttpServletRequest;
import java.net.URI;

import org.forgerock.json.resource.http.HttpContext;
import org.forgerock.openam.core.CoreWrapper;
import org.forgerock.openam.core.realms.Realm;
import org.forgerock.openam.core.realms.RealmLookupException;
import org.forgerock.openam.utils.OpenAMSettings;
import org.forgerock.openam.utils.StringUtils;
import org.forgerock.util.Reject;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Provides the base URL for the OpenAM instance. Subclasses may use the HttpServletRequest
 * to deduce the URL, or work it out by some other means.
 */
public abstract class BaseURLProvider {

    private final Logger logger = LoggerFactory.getLogger("amRequestUtils");
    private String contextPath;
    private CoreWrapper coreWrapper;

    void setContextPath(String contextPath) {
        this.contextPath = contextPath;
    }

    void setCoreWrapper(CoreWrapper coreWrapper) {
        this.coreWrapper = coreWrapper;
    }

    /**
     * The implementation of getting the base URL without the context path, which will be added if configured.
     * @param request The servlet request.
     * @return The base URL.
     */
    protected abstract String getBaseURL(HttpServletRequest request);

    /**
     * The implementation of getting the base URL without the context path, which will be added if configured.
     * @param context The http context.
     * @return The base URL.
     */
    protected abstract String getBaseURL(HttpContext context);

    /**
     * Initialise the provider from the settings.
     * @param settings The settings access object.
     * @param realm The realm that is being configured.
     */
    abstract void init(OpenAMSettings settings, String realm);

    /**
     * Gets the base URL to use in the response to the request.
     * @param request The current request.
     * @return The base URL. This will never end in a / character.
     */
    public String getRootURL(HttpServletRequest request) {
        return formatURL(getBaseURL(request));
    }

    /**
     * Gets the base URL to use in the http context.
     * @param context The current http context.
     * @return The base URL. This will never end in a / character.
     */
    public String getRootURL(HttpContext context) {
        return formatURL(getBaseURL(context));
    }

    /**
     * Gets the base URL to use in the response to the request.
     * @param request The current request.
     * @param basePath The base path before the relative subrealm path, e.g. {@code /json}, {@code /uma},
     * {@code /oauth2}, etc.
     * @param realm The realm the URL should target. Should be an absolute realm path, starting with a /.
     * @return The base URL. This will never end in a / character.
     * @throws InvalidBaseUrlException When the realm is not a subrealm or the same realm as that deduced from
     * the root URL for the base URL provider.
     */
    public String getRealmURL(HttpServletRequest request, String basePath, Realm realm) throws InvalidBaseUrlException {
        try {
            Realm dnsRealm = Realm.of(URI.create(request.getRequestURL().toString()).getHost());
            return getRealmURL(getRootURL(request), basePath, dnsRealm, realm);
        } catch (RealmLookupException e) {
            throw new InvalidBaseUrlException(e.getMessage(), e);
        }
    }

    /**
     * Gets the base URL to use in the http context.
     * @param context The current http context.
     * @param basePath The base path before the relative subrealm path, e.g. {@code /json}, {@code /uma},
     * {@code /oauth2}, etc.
     * @param realm The realm the URL should target. Should be an absolute realm path, starting with a /.
     * @return The base URL. This will never end in a / character.
     * @throws InvalidBaseUrlException When the realm is not a subrealm or the same realm as that deduced from
     * the root URL for the base URL provider.
     */
    public String getRealmURL(HttpContext context, String basePath, Realm realm) throws InvalidBaseUrlException {
        try {
            Realm dnsRealm = Realm.of(URI.create(context.asContext(HttpContext.class).getPath()).getHost());
            return getRealmURL(getRootURL(context), basePath, dnsRealm, realm);
        } catch (RealmLookupException e) {
            throw new InvalidBaseUrlException(e.getMessage(), e);
        }
    }

    private String getRealmURL(String rootUrl, String basePath, Realm dnsRealm, Realm absoluteRealm)
            throws InvalidBaseUrlException {
        if (dnsRealm.equals(absoluteRealm)) {
            return rootUrl + basePath;
        } else {
            return rootUrl + realmSubPath(absoluteRealm.asPath(), basePath);
        }
    }

    /**
     * Gets the contextPath.
     * @return The contextPath.
     */
    public String getContextPath() {
        return contextPath;
    }

    /**
     * Format the URL
     * @param baseUrl base url to reformat
     * @return the reformat base URL
     */
    private String formatURL(String baseUrl) {
        if (StringUtils.isNotBlank(contextPath)) {
            baseUrl += contextPath;
        }
        if (baseUrl.endsWith("/")) {
            baseUrl = baseUrl.substring(0, baseUrl.length() - 1);
        }
        return baseUrl;
    }

    private String realmSubPath(String realm, String basePath) throws InvalidBaseUrlException {
        Reject.ifFalse(basePath.startsWith("/"), "basePath must start with a / character");
        Reject.ifTrue(basePath.endsWith("/"), "basePath must not end with a / character");
        StringBuilder sb = new StringBuilder(basePath);
        sb.append("/realms/root");
        for (String realmPart : realm.split("/")) {
            if (!StringUtils.isEmpty(realmPart)) {
                sb.append("/realms/").append(realmPart);
            }
        }
        return sb.toString();
    }
}
