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
 * Copyright 2014-2016 ForgeRock AS.
 * Portions Copyrighted 2018 Open Source Solution Technology Corporation
 * Portions copyright 2025 3A Systems LLC.
 */

package org.forgerock.oauth2.core;

import jakarta.inject.Inject;
import java.io.IOException;
import java.util.Collection;
import java.util.Collections;
import java.util.Locale;
import java.util.Map;
import java.util.Set;

import com.google.inject.assistedinject.Assisted;
import com.google.common.collect.ClassToInstanceMap;
import com.google.common.collect.MutableClassToInstanceMap;
import org.forgerock.json.JsonValue;
import org.forgerock.openam.oauth2.OAuth2Constants.EndpointType;
import org.forgerock.openam.rest.representations.JacksonRepresentationFactory;
import org.forgerock.openam.rest.service.RestletRealmRouter;
import org.restlet.Request;
import org.restlet.data.Form;
import org.restlet.data.MediaType;
import org.restlet.data.Method;
import org.restlet.ext.jackson.JacksonRepresentation;
import org.forgerock.openam.rest.jakarta.servlet.ServletUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * An abstraction of the actual request so as to allow the core of the OAuth2 provider to be agnostic of the library
 * used to translate the HTTP request.
 *
 * @since 12.0.0
 * 
 */
public class OAuth2Request {

    private final ClassToInstanceMap<Token> tokens = MutableClassToInstanceMap.create();
    private final Logger logger = LoggerFactory.getLogger("OAuth2Provider");
    private final Request request;
    private final JacksonRepresentationFactory jacksonRepresentationFactory;
    private String sessionId;
    private JsonValue body;
    private ClientRegistration clientRegistration;

    /**
     * Constructs a new RestletOAuth2Request.
     *
     * @param jacksonRepresentationFactory The factory class for {@link JacksonRepresentation}.
     * @param request The Restlet request.
     */
    @Inject
    public OAuth2Request(JacksonRepresentationFactory jacksonRepresentationFactory, @Assisted Request request) {
        this.jacksonRepresentationFactory = jacksonRepresentationFactory;
        this.request = request;
    }

    /**
     * Gets the actual underlying request.
     *
     * @return The underlying request.
     */
    public Request getRequest() {
        return request;
    }

    /**
     * Gets the specified parameter from the request.
     * <br/>
     * It is up to the implementation to determine how and where it gets the parameter from on the request, i.e.
     * query parameters, request attributes, etc.
     *
     * @param name The name of the parameter.
     * @param <T> The type of the parameter.
     * @return The parameter value.
     */
    public <T> T getParameter(String name) {
        Object value = getAttribute(request, name);
        if (value != null) {
            return (T) value;
        }

        //query param priority over body
        if (getQueryParameter(request, name) != null) {
            return (T) getQueryParameter(request, name);
        }

        if (request.getMethod().equals(Method.POST)) {
            if (request.getEntity() != null) {
                if (MediaType.APPLICATION_WWW_FORM.equals(request.getEntity().getMediaType())) {
                    Form form = new Form(request.getEntity());
                    // restore the entity body
                    request.setEntity(form.getWebRepresentation());
                    return (T) form.getValuesMap().get(name);
                } else if (MediaType.APPLICATION_JSON.equals(request.getEntity().getMediaType())) {
                    return (T) getBody().get(name).getObject();
                }
            }
        }
        return null;
    }

    /**
     * Gets the count of the parameter present in the request with the given name
     *
     * @param name The name of the parameter
     * @return  The count of the the parameter with the given name
     */
    public int getParameterCount(String name) {
        return request.getResourceRef().getQueryAsForm().subList(name).size();
    }

    /**
     *
     * Gets the name of the parameters in the current request
     *
     *
     * @return The parameter names in the request
     */
    public Set<String> getParameterNames() {

        if (request.getMethod().equals(Method.GET)) {
            return request.getResourceRef().getQueryAsForm().getNames();
        } else if (request.getMethod().equals(Method.POST)) {
            if (request.getEntity() != null) {
                if (MediaType.APPLICATION_WWW_FORM.equals(request.getEntity().getMediaType())) {
                    Form form = new Form(request.getEntity());
                    // restore the entity body
                    request.setEntity(form.getWebRepresentation());
                    return  form.getNames();
                } else if (MediaType.APPLICATION_JSON.equals(request.getEntity().getMediaType())) {
                    return getBody().keys();
                }
            }
        }
        return Collections.emptySet();
    }

    /**
     * Gets the value for an attribute from the request with the specified name.
     *
     * @param request The request.
     * @param name The name.
     * @return The attribute value, may be {@code null}
     */
    private Object getAttribute(Request request, String name) {
        return request.getAttributes().get(name);
    }

    /**
     * Gets the value for a query parameter from the request with the specified name.
     *
     * @param request The request.
     * @param name The name.
     * @return The query parameter value, may be {@code null}.
     */
    private String getQueryParameter(Request request, String name) {
        return request.getResourceRef().getQueryAsForm().getValuesMap().get(name);
    }

    /**
     * Gets the body of the request.
     * <br/>
     * Note: reading of the body maybe a one time only operation, so the implementation needs to cache the content
     * of the body so multiple calls to this method do not behave differently.
     * <br/>
     * This method should only ever be called for access and refresh token request and requests to the userinfo and
     * tokeninfo endpoints.
     *
     * @return The body of the request.
     */
    public JsonValue getBody() {
        if (body == null) {
            final JacksonRepresentation<Map> representation =
                    jacksonRepresentationFactory.create(request.getEntity(), Map.class);
            try {
                body = new JsonValue(representation.getObject());
            } catch (IOException e) {
                logger.error(e.getMessage());
                return JsonValue.json(JsonValue.object());
            }
        }
        return body;
    }

    /**
     * Set a Token that is in play for this request.
     * @param tokenClass The token type.
     * @param token The token instance.
     * @param <T> The type of token.
     */
    public <T extends Token> void setToken(Class<T> tokenClass, T token) {
        tokens.putInstance(tokenClass, token);
    }

    /**
     * Get a Token that is in play for this request.
     * @param tokenClass The token type.
     * @param <T> The type of token.
     * @return The token instance.
     */
    public <T extends Token> T getToken(Class<T> tokenClass) {
        return tokens.getInstance(tokenClass);
    }

    /**
     * Get all the tokens that have been used in this request.
     * @return The token instances.
     */
    public Collection<Token> getTokens() {
        return tokens.values();
    }

    /**
     * Sets the user's session for this request.
     *
     * @param sessionId The user's session.
     */
    public void setSession(String sessionId) {
        this.sessionId = sessionId;
    }

    /**
     * Gets the user's session for this request.
     *
     * @return The user's session.
     */
    public String getSession() {
        return sessionId;
    }

    /**
     * Get the request locale.
     * @return The Locale object.
     */
    public Locale getLocale() {
        return ServletUtils.getRequest(request).getLocale();
    }

    /**
     * Get the OAuth2 client registration of the request.
     *
     * @return The client registration.
     */
    public ClientRegistration getClientRegistration() {
        return clientRegistration;
    }

    /**
     * Creates an {@code OAuth2Request} which holds the provided realm only.
     *
     * @param realm The request realm.
     * @return An {@code OAuth2Request}.
     */
    public static OAuth2Request forRealm(String realm) {
        return new RealmOnlyOAuth2Request(realm);
    }

    /**
     * Set the OAuth2 client registration.
     *
     * @param clientRegistration The client registration.
     */
    public void setClientRegistration(ClientRegistration clientRegistration) {
        this.clientRegistration = clientRegistration;
    }

    private static class RealmOnlyOAuth2Request extends OAuth2Request {

        private final String realm;

        private RealmOnlyOAuth2Request(String realm) {
            super(null, null);
            this.realm = realm;
        }

        @Override
        public Request getRequest() {
            throw new UnsupportedOperationException("Realm parameter only OAuth2Request");
        }

        @Override
        public <T> T getParameter(String name) {
            if ("realm".equals(name)) {
                return (T) realm;
            }
            throw new UnsupportedOperationException("Realm parameter only OAuth2Request");
        }

        @Override
        public JsonValue getBody() {
            return null;
        }

        @Override
        public int getParameterCount(String name)  { throw new UnsupportedOperationException(); }

        @Override
        public Set<String> getParameterNames() { throw new UnsupportedOperationException(); }

        @Override
        public java.util.Locale getLocale() {
            throw new UnsupportedOperationException();
        }
    }
    
    /**
     * Get EndpointType.
     * @return EndpointType
     */
    public EndpointType getEndpointType() {
        String resourcePath = null;
        String realmUrl = (String) request.getAttributes().get(RestletRealmRouter.REALM_URL);
        String resourceUrl = request.getResourceRef().toString(false, false);
        if (resourceUrl.startsWith(realmUrl)) {
            resourcePath = resourceUrl.substring(realmUrl.length());
        }
       return EndpointType.get(resourcePath);
    }
}
