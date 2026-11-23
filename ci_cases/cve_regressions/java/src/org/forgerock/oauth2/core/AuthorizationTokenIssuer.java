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
 * Portions Copyrighted 2015 Nomura Research Institute, Ltd.
 * Portions copyright 2025 3A Systems LLC.
 */

package org.forgerock.oauth2.core;

import static org.forgerock.oauth2.core.Utils.splitResponseType;
import static org.forgerock.openam.oauth2.OAuth2Constants.JWTTokenParams.ISS;
import static org.forgerock.openam.oauth2.OAuth2Constants.Params.*;

import jakarta.inject.Inject;
import jakarta.inject.Singleton;
import java.util.Collections;
import java.util.Comparator;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;

import org.forgerock.oauth2.core.exceptions.InvalidClientException;
import org.forgerock.oauth2.core.exceptions.InvalidScopeException;
import org.forgerock.oauth2.core.exceptions.NotFoundException;
import org.forgerock.oauth2.core.exceptions.ServerException;
import org.forgerock.oauth2.core.exceptions.UnsupportedResponseTypeException;
import org.forgerock.openam.oauth2.OAuth2Constants;
import org.forgerock.openam.oauth2.OAuth2UrisFactory;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Issues Authorization Tokens requested by OAuth2 authorize requests.
 *
 * @since 12.0.0
 */
@Singleton
public class AuthorizationTokenIssuer {

    private final Logger logger = LoggerFactory.getLogger("OAuth2Provider");
    private final OAuth2UrisFactory urisFactory;

    @Inject
    public AuthorizationTokenIssuer(OAuth2UrisFactory urisFactory) {
        this.urisFactory = urisFactory;
    }

    /**
     * Issues tokens for the OAuth2 authorize request.
     *
     * @param request The OAuth2 request.
     * @param clientRegistration The client's registration.
     * @param resourceOwner The resource owner.
     * @param authorizationScope The authorization scope.
     * @param providerSettings An instance of the OAuth2ProviderSettings.
     * @return An AuthorizationToken.
     * @throws InvalidClientException If either the request does not contain the client's id or the client fails to be
     *          authenticated.
     * @throws UnsupportedResponseTypeException If the requested response type is not supported by either the client
     *          or the OAuth2 provider.
     * @throws ServerException If any internal server error occurs.
     * @throws InvalidScopeException If the requested scope is invalid, unknown, or malformed.
     * @throws NotFoundException If the realm does not have an OAuth 2.0 provider service.
     */
    public AuthorizationToken issueTokens(OAuth2Request request, ClientRegistration clientRegistration,
            ResourceOwner resourceOwner, Set<String> authorizationScope, OAuth2ProviderSettings providerSettings)
            throws InvalidClientException, UnsupportedResponseTypeException, ServerException, InvalidScopeException,
            NotFoundException {

        //issue tokens
        final Set<String> requestedResponseTypes =
                splitResponseType(request.<String>getParameter(RESPONSE_TYPE));
        if (Utils.isEmpty(requestedResponseTypes)) {
            logger.debug("Response type is not supported");
            throw new UnsupportedResponseTypeException("Response type is not supported");
        }

        final Set<String> validatedScope = providerSettings.validateAccessTokenScope(clientRegistration,
                authorizationScope, request);

        final Map<String, ResponseTypeHandler> allowedResponseTypes = providerSettings.getAllowedResponseTypes();

        final String tokenType = clientRegistration.getAccessTokenType();
        final String clientId = clientRegistration.getClientId();
        final String redirectUri = request.getParameter(REDIRECT_URI);
        final String nonce = request.getParameter(OAuth2Constants.Custom.NONCE);
        final String codeChallenge = request.getParameter(OAuth2Constants.Custom.CODE_CHALLENGE);
        final String codeChallengeMethod = request.getParameter(OAuth2Constants.Custom.CODE_CHALLENGE_METHOD);

        final Map<String, Token> tokens = new HashMap<String, Token>();
        boolean returnAsFragment = false;

        final List<String> sortedResponseTypes =
                Utils.asSortedList(requestedResponseTypes,
                        new KeyStringComparator(OAuth2Constants.JWTTokenParams.ID_TOKEN));

        for (final String responseType : sortedResponseTypes) {

            if (Utils.isEmpty(responseType)) {
                throw new UnsupportedResponseTypeException("Response type is not supported");
            }

            final ResponseTypeHandler responseTypeHandler = allowedResponseTypes.get(responseType);

            final Map.Entry<String, Token> token = responseTypeHandler.handle(tokenType, validatedScope,
                    resourceOwner, clientId, redirectUri, nonce, request, codeChallenge, codeChallengeMethod);

            if (token != null) {

                if (tokens.containsKey(token.getKey())) {
                    logger.debug("Returning multiple response types with the same url value");
                    throw new UnsupportedResponseTypeException("Returning multiple response types with the same url "
                            + "value");
                }

                tokens.put(token.getKey(), token.getValue());

                if (!returnAsFragment) {
                    final OAuth2Constants.UrlLocation returnLocation = responseTypeHandler.getReturnLocation();
                    returnAsFragment = OAuth2Constants.UrlLocation.FRAGMENT.equals(returnLocation);
                }

            }
        }

        final Map<String, String> tokenMap = flattenTokens(tokens);

        //plugin point for provider to add additional entries to tokenMap
        final Map<String, String> additionalData = providerSettings.additionalDataToReturnFromAuthorizeEndpoint(
                Collections.unmodifiableMap(tokens), request);
        if (!Utils.isEmpty(additionalData)) {
            final String returnLoc = additionalData.remove("returnLocation");
            if (!Utils.isEmpty(returnLoc)) {
                final OAuth2Constants.UrlLocation returnLocation =
                        OAuth2Constants.UrlLocation.valueOf(returnLoc.toUpperCase());
                if (!returnAsFragment && OAuth2Constants.UrlLocation.FRAGMENT.equals(returnLocation)) {
                    returnAsFragment = true;
                }
            }
            tokenMap.putAll(additionalData);
        }

        // Always echo scope back to the requester even if identical - consistent with access_token endpoint.
        tokenMap.put(SCOPE, Utils.joinScope(validatedScope));

        if (request.getParameter(STATE) != null) {
            tokenMap.put(STATE, request.<String>getParameter(STATE));
        }

        if (!tokenMap.containsKey("id_token")) {
            tokenMap.put(ISS, urisFactory.get(request).getIssuer());
            tokenMap.put(CLIENT_ID, clientRegistration.getClientId());
        }
        return new AuthorizationToken(tokenMap, returnAsFragment);
    }

    /**
     * Flattens a {@code Map} of token name and Token into a single {@code Map} of the token name and any additional
     * information from an access token.
     *
     * @param tokens The {@code Map} of tokens.
     * @return A {@code Map} of the flattened tokens.
     * @throws ServerException If any internal server error occurs.
     */
    private Map<String, String> flattenTokens(Map<String, Token> tokens) throws ServerException {

        final Map<String, String> tokenMap = new HashMap<String, String>();

        for (final Map.Entry<String, Token> entry : tokens.entrySet()) {
            final Map<String, Object> token = entry.getValue().toMap();
            if (!tokenMap.containsKey(entry.getKey())) {
                tokenMap.put(entry.getKey(), entry.getValue().getTokenId());
            }
            //if access token add extra fields
            if (entry.getValue().getTokenName().equalsIgnoreCase(ACCESS_TOKEN)) {
                for (final Map.Entry<String, Object> entryInMap : token.entrySet()) {
                    if (!tokenMap.containsKey(entryInMap.getKey())) {
                        tokenMap.put(entryInMap.getKey(), entryInMap.getValue().toString());
                    }
                }
            }
        }

        return tokenMap;
    }

    /**
     * Comparator that takes a given String in its ctor which is moved to the end
     * of the list. The order of other elements is undetermined.
     */
    private class KeyStringComparator implements Comparator<String> {

        private final String key;

        public KeyStringComparator(String key) {
            this.key = key;
        }

        @Override
        public int compare(String first, String second) {
            if (first.equals(key)) {
                return 1;
            } else if (second.equals(key)) {
                return -1;
            } else {
                return 0;
            }
        }
    }
}
