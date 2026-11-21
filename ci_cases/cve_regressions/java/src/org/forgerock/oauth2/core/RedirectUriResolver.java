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
 *  Copyright 2016 ForgeRock AS.
 * Portions copyright 2025 3A Systems LLC.
 *
 */

package org.forgerock.oauth2.core;

import static org.forgerock.openam.oauth2.OAuth2Constants.Params.CLIENT_ID;
import static org.forgerock.openam.oauth2.OAuth2Constants.Params.REDIRECT_URI;
import static org.forgerock.oauth2.core.Utils.isEmpty;

import jakarta.inject.Inject;
import java.net.URI;
import java.util.Set;

import org.forgerock.oauth2.core.exceptions.InvalidClientException;
import org.forgerock.oauth2.core.exceptions.InvalidRequestException;
import org.forgerock.oauth2.core.exceptions.NotFoundException;

/**
 * Resolves the URI to be redirected to after the authorization
 *
 * @since 14.0.0
 */

public class RedirectUriResolver {

    private final ClientRegistrationStore clientRegistrationStore;

    /**
     * Constructs the new RedirectUriResolverImpl instance
     *
     * @param clientRegistrationStore An instance of the ClientRegistrationStore.
     */
    @Inject
    public RedirectUriResolver(ClientRegistrationStore clientRegistrationStore) {
        this.clientRegistrationStore = clientRegistrationStore;
    }


    /**
     * Resolves the redirect URI
     *
     * @param request The OAuth2Request for the client requesting authorization. Must not be {@code null}.
     * @return The the redirection end point URI string
     * @throws InvalidClientException If client cannot be retrieved from the store.
     * @throws NotFoundException If requested realm doesn't exist
     * @throws InvalidRequestException If the request is missing any required parameters or is otherwise malformed.
     */
    public String resolve(OAuth2Request request) throws NotFoundException, InvalidClientException, InvalidRequestException {

        String redirectUri = null;
        ClientRegistration clientRegistration = clientRegistrationStore.get(request.<String>
                getParameter(CLIENT_ID), request);

        if (clientRegistration != null) {
            Set<URI> redirectUris = clientRegistration.getRedirectUris();

            if (isEmpty(redirectUris)) {
                throw new InvalidRequestException("Failed to resolve the redirect URI, no URI's registered");
            }
            redirectUri = request.getParameter(REDIRECT_URI);
            if (isEmpty(redirectUri) && redirectUris.size() == 1) {
                redirectUri = redirectUris.iterator().next().toString();
            }
        }

        if (isEmpty(redirectUri)) {
            throw new InvalidRequestException("Failed to resolve the redirect URI");
        }
        return redirectUri;
    }

}
