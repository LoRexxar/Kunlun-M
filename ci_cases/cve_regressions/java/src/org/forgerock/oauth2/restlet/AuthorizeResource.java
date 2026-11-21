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
 * Portions copyright 2025 3A Systems LLC.
 */

package org.forgerock.oauth2.restlet;

import jakarta.inject.Inject;
import jakarta.inject.Named;
import java.util.Set;

import org.forgerock.oauth2.core.AuthorizationService;
import org.forgerock.oauth2.core.AuthorizationToken;
import org.forgerock.oauth2.core.OAuth2Request;
import org.forgerock.oauth2.core.OAuth2RequestFactory;
import org.forgerock.oauth2.core.RedirectUriResolver;
import org.forgerock.oauth2.core.ResourceOwnerSessionValidator;
import org.forgerock.oauth2.core.exceptions.CsrfException;
import org.forgerock.oauth2.core.exceptions.DuplicateRequestParameterException;
import org.forgerock.oauth2.core.exceptions.InvalidClientException;
import org.forgerock.oauth2.core.exceptions.OAuth2Exception;
import org.forgerock.oauth2.core.exceptions.OAuth2ProviderNotFoundException;
import org.forgerock.oauth2.core.exceptions.RedirectUriMismatchException;
import org.forgerock.oauth2.core.exceptions.ResourceOwnerAuthenticationRequired;
import org.forgerock.oauth2.core.exceptions.ResourceOwnerConsentRequired;
import org.forgerock.openam.services.baseurl.BaseURLProviderFactory;
import org.forgerock.openam.xui.XUIState;
import org.restlet.representation.Representation;
import org.restlet.resource.Get;
import org.restlet.resource.Post;
import org.restlet.routing.Router;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Handles requests to the OAuth2 authorize endpoint.
 *
 * @since 12.0.0
 */
public class AuthorizeResource extends ConsentRequiredResource {

    private final Logger logger = LoggerFactory.getLogger("OAuth2Provider");

    private final OAuth2RequestFactory requestFactory;
    private final AuthorizationService authorizationService;
    private final ExceptionHandler exceptionHandler;
    private final OAuth2Representation representation;
    private final Set<AuthorizeRequestHook> hooks;
    private final RedirectUriResolver redirectUriResolver;


    /**
     * Constructs a new AuthorizeResource.
     *
     * @param requestFactory An instance of the OAuth2RequestFactory.
     * @param authorizationService An instance of the AuthorizationService.
     * @param exceptionHandler An instance of the ExceptionHandler.
     * @param representation An instance of the OAuth2Representation.
     */
    @Inject
    public AuthorizeResource(OAuth2RequestFactory requestFactory, AuthorizationService authorizationService,
            ExceptionHandler exceptionHandler, OAuth2Representation representation, Set<AuthorizeRequestHook> hooks,
            XUIState xuiState, @Named("OAuth2Router") Router router, BaseURLProviderFactory baseURLProviderFactory,
            RedirectUriResolver redirectUriResolver, ResourceOwnerSessionValidator resourceOwnerSessionValidator) {
        super(router, baseURLProviderFactory, xuiState, resourceOwnerSessionValidator);
        this.requestFactory = requestFactory;
        this.authorizationService = authorizationService;
        this.exceptionHandler = exceptionHandler;
        this.representation = representation;
        this.hooks = hooks;
        this.redirectUriResolver = redirectUriResolver;
    }

    /**
     * Handles GET requests to the OAuth2 authorize endpoint.
     * <br/>
     * This method will be called when a client has requested a resource owner grants it authorization to access a
     * resource.
     *
     * @return The body to be sent in the response to the user agent.
     * @throws OAuth2RestletException If a OAuth2 error occurs whilst processing the authorization request.
     */
    @Get
    public Representation authorize() throws OAuth2RestletException {

        final OAuth2Request request = requestFactory.create(getRequest());

        for (AuthorizeRequestHook hook : hooks) {
            hook.beforeAuthorizeHandling(request, getRequest(), getResponse());
        }

        try {
            final AuthorizationToken authorizationToken = authorizationService.authorize(request);

            final String redirectUri = redirectUriResolver.resolve(request);

            Representation response = representation.toRepresentation(getContext(), getRequest(), getResponse(), authorizationToken,
                    redirectUri);

            for (AuthorizeRequestHook hook : hooks) {
                hook.afterAuthorizeSuccess(request, getRequest(), getResponse());
            }

            return response;

        } catch (IllegalArgumentException e) {
            if (e.getMessage().contains("client_id")) {
                throw new OAuth2RestletException(400, "invalid_request", e.getMessage(),
                        request.<String>getParameter("state"));
            }
            throw new OAuth2RestletException(400, "invalid_request", e.getMessage(),
                    request.<String>getParameter("redirect_uri"), request.<String>getParameter("state"));
        } catch (ResourceOwnerAuthenticationRequired e) {
            throw new OAuth2RestletException(e.getStatusCode(), e.getError(), e.getMessage(),
                    e.getRedirectUri().toString(), null);
        } catch (ResourceOwnerConsentRequired e) {
            return representation.getRepresentation(getContext(), request, "authorize.ftl",
                    getDataModel(e, request));
        } catch (InvalidClientException e) {
            throw new OAuth2RestletException(e.getStatusCode(), e.getError(), e.getMessage(),
                    request.<String>getParameter("state"));
        } catch (RedirectUriMismatchException e) {
            throw new OAuth2RestletException(e.getStatusCode(), e.getError(), e.getMessage(),
                    request.<String>getParameter("state"));
        } catch (DuplicateRequestParameterException e) {
            throw new OAuth2RestletException(400, "invalid_request", e.getMessage(),
                    request.<String>getParameter("state"));
        } catch (OAuth2ProviderNotFoundException e) {
            throw new OAuth2RestletException(e.getStatusCode(), e.getError(), e.getMessage(),
                    request.<String>getParameter("state"));
        } catch (OAuth2Exception e) {
            throw new OAuth2RestletException(e.getStatusCode(), e.getError(), e.getMessage(),
                    request.<String>getParameter("redirect_uri"), request.<String>getParameter("state"),
                    e.getParameterLocation());
        }
    }

    /**
     * Handles POST requests to the OAuth2 authorize endpoint.
     * <br/>
     * This method will be called when a user has given their consent for an authorization request.
     *
     * @param entity The entity on the request.
     * @return The body to be sent in the response to the user agent.
     * @throws OAuth2RestletException If a OAuth2 error occurs whilst processing the authorization request.
     */
    @Post
    public Representation authorize(Representation entity) throws OAuth2RestletException {

        final OAuth2Request request = requestFactory.create(getRequest());

        for (AuthorizeRequestHook hook : hooks) {
            hook.beforeAuthorizeHandling(request, getRequest(), getResponse());
        }

        final boolean consentGiven = "allow".equalsIgnoreCase(request.<String>getParameter("decision"));
        final boolean saveConsent = "on".equalsIgnoreCase(request.<String>getParameter("save_consent"));

        try {
            final AuthorizationToken authorizationToken = authorizationService.authorize(request, consentGiven,
                    saveConsent);

            final String redirectUri = redirectUriResolver.resolve(request);
            Representation response = representation.toRepresentation(getContext(), getRequest(), getResponse(), authorizationToken,
                    redirectUri);

            for (AuthorizeRequestHook hook : hooks) {
                hook.afterAuthorizeSuccess(request, getRequest(), getResponse());
            }

            return response;

        } catch (ResourceOwnerAuthenticationRequired e) {
            throw new OAuth2RestletException(e.getStatusCode(), e.getError(), e.getMessage(),
                    e.getRedirectUri().toString(), null);
        } catch (InvalidClientException e) {
            throw new OAuth2RestletException(e.getStatusCode(), e.getError(), e.getMessage(),
                    request.<String>getParameter("state"));
        } catch (RedirectUriMismatchException e) {
            throw new OAuth2RestletException(e.getStatusCode(), e.getError(), e.getMessage(),
                    request.<String>getParameter("state"));
        } catch (DuplicateRequestParameterException e) {
            throw new OAuth2RestletException(400, "invalid_request", e.getMessage(),
                    request.<String>getParameter("state"));
        } catch (CsrfException e) {
            throw new OAuth2RestletException(400, "bad_request", e.getMessage(),
                    request.<String>getParameter("state"));
        } catch (OAuth2Exception e) {
            throw new OAuth2RestletException(e.getStatusCode(), e.getError(), e.getMessage(),
                    request.<String>getParameter("redirect_uri"), request.<String>getParameter("state"),
                    e.getParameterLocation());
        }
    }

    /**
     * Handles any exception that is thrown when processing a OAuth2 authorization request.
     *
     * @param throwable The throwable.
     */
    @Override
    protected void doCatch(Throwable throwable) {
        exceptionHandler.handle(throwable, getContext(), getRequest(), getResponse());
    }
}
