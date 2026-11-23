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
 * Copyright 2014 ForgeRock AS.
 */

package org.forgerock.oauth2.core;

import java.util.Map;

/**
 * Models an authorization token that is returned from the OAuth2 authorize request.
 *
 * @since 12.0.0
 */
public class AuthorizationToken {

    private final Map<String, String> token;
    private final boolean fragment;

    /**
     * Constructs a new AuthorizationToken.
     *
     * @param token A {@code Map} of tokens to be returned.
     * @param fragment {@code true} if the tokens should be returned as a fragment of the URL.
     */
    public AuthorizationToken(Map<String, String> token, boolean fragment) {
        this.token = token;
        this.fragment = fragment;
    }

    /**
     * Gets the tokens.
     *
     * @return The tokens.
     */
    public Map<String, String> getToken() {
        return token;
    }

    /**
     * Whether the tokens should be returned as a fragment of the URL.
     *
     * @return {@code true} if the tokens should be returned as a fragment of the URL.
     */
    public boolean isFragment() {
        return fragment;
    }
}
