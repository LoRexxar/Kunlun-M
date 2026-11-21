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

import java.util.HashMap;
import jakarta.inject.Inject;
import org.forgerock.oauth2.core.AuthorizationToken;
import org.forgerock.oauth2.core.OAuth2Request;
import org.forgerock.openam.oauth2.OAuth2Constants;
import org.forgerock.oauth2.core.OAuth2RequestFactory;
import org.restlet.Context;
import org.restlet.Request;
import org.restlet.Response;
import org.restlet.data.Form;
import org.restlet.data.Parameter;
import org.restlet.data.Reference;
import org.restlet.data.Status;
import org.restlet.ext.freemarker.TemplateRepresentation;
import org.restlet.representation.Representation;
import org.restlet.resource.ResourceException;
import org.restlet.routing.Redirector;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.util.Iterator;
import java.util.Map;

import static org.forgerock.oauth2.core.Utils.isEmpty;

/**
 * Handles processing user consent and error pages to Restlet representations.
 *
 * @since 12.0.0
 */
public class OAuth2Representation {

    private final OAuth2RequestFactory requestFactory;
    private final Logger logger = LoggerFactory.getLogger("OAuth2Provider");

    @Inject
    public OAuth2Representation(OAuth2RequestFactory requestFactory) {
        this.requestFactory = requestFactory;
    }

    /**
     * Gets the appropriate representation to send to the user agent based from the specified parameters.
     *
     * @param context The Restlet context.
     * @param templateName The name of the template to display.
     * @param dataModel The data model to display on the page.
     * @return A representation of the page to send to the user agent.
     */
    public Representation getRepresentation(Context context, OAuth2Request request, String templateName,
            Map<String, Object> dataModel) {

        final String display = request.getParameter("display");
        OAuth2Constants.DisplayType displayType = OAuth2Constants.DisplayType.PAGE;
        if (!isEmpty(display)) {
            displayType = Enum.valueOf(OAuth2Constants.DisplayType.class, display.toUpperCase());
        }

        final Representation representation;
        if (display != null && display.equalsIgnoreCase("popup")) {
            Representation popup = getRepresentation(context, displayType.getFolder(), "authorize.ftl", dataModel);

            try {
                dataModel.put("htmlCode", popup.getText());
            } catch (IOException e) {
                logger.error("Server can not serve the content of authorization page");
                throw new ResourceException(Status.CLIENT_ERROR_BAD_REQUEST,
                        "Server can not serve the content of authorization page");
            }
            representation = getRepresentation(context, displayType.getFolder(), "popup.ftl", dataModel);
        } else {
            representation = getRepresentation(context, displayType.getFolder(), templateName, dataModel);
        }
        if (representation != null) {
            return representation;
        }
        logger.error("Server can not serve the content of authorization page");
        throw new ResourceException(Status.CLIENT_ERROR_BAD_REQUEST,
                "Server can not serve the content of authorization page");
    }

    /**
     * Gets the appropriate representation to send to the user agent based from the specified parameters.
     * <br/>
     * The possible values for the display are: page, popup, touch, wap.
     *
     * @param context The Restlet context.
     * @param display The display type of the page.
     * @param templateName The name of the template to display.
     * @param dataModel The data model to display on the page.
     * @return A representation of the page to send to the user agent.
     */
    Representation getRepresentation(Context context, String display, String templateName, Map<String, ?> dataModel) {
        final String reference = "templates/" + (display != null ? display : "page") + "/" + templateName;
        final TemplateRepresentation result = getTemplateFactory(context).getTemplateRepresentation(reference);
        if (result != null) {
            result.setDataModel(dataModel);
        }
        return result;
    }

    /**
     * Gets an instance of the TemplateFactory.
     *
     * @param context The Restlet context.
     * @return An instance of the TemplateFactory.
     */
    private TemplateFactory getTemplateFactory(Context context) {
        Object factory = context.getAttributes().get(TemplateFactory.class.getName());
        if (factory instanceof TemplateFactory) {
            return (TemplateFactory) factory;
        }

        final TemplateFactory newFactory = TemplateFactory.newInstance(context);
        context.getAttributes().put(TemplateFactory.class.getName(), newFactory);
        return newFactory;
    }

    /**
     * Converts the authorization token into a representation to send back to the user agent.
     *
     * @param context The Restlet context.
     * @param request The Restlet request.
     * @param response The Restlet response.
     * @param authorizationToken The authorization token.
     * @param redirectUri The redirect uri.
     * @return The representation to send to the user agent.
     */
    Representation toRepresentation(Context context, Request request, Response response,
            AuthorizationToken authorizationToken, String redirectUri) {

        final Form tokenForm = toForm(authorizationToken);

        final Reference redirectReference = new Reference(redirectUri);

        if (authorizationToken.isFragment()) {
            redirectReference.setFragment(tokenForm.getQueryString());
        } else {
            final Iterator<Parameter> iter = tokenForm.iterator();
            while (iter.hasNext()) {
                redirectReference.addQueryParameter(iter.next());
            }
        }

        if (isFormPostRequest(requestFactory.create(request))) {
            return getFormPostRepresentation(context, authorizationToken, redirectReference.toString());
        }

        final Redirector dispatcher = new Redirector(context, redirectReference.toString(),
                Redirector.MODE_CLIENT_FOUND);
        dispatcher.handle(request, response);

        return response == null ? null : response.getEntity();
    }

    private Representation getFormPostRepresentation(Context context, AuthorizationToken authorizationToken,
                                                     String redirectUri) {
        Map<String, Object> dataModel = new HashMap<>();
        dataModel.put("redirectUri", redirectUri);
        dataModel.put("formValues", authorizationToken.getToken());

        final String reference = "templates/FormPostResponse.ftl";
        final TemplateRepresentation result = getTemplateFactory(context).getTemplateRepresentation(reference);
        if (result != null) {
            result.setDataModel(dataModel);
        }
        return result;
    }

    private boolean isFormPostRequest(OAuth2Request request) {
        return OAuth2Constants.Custom.FORM_POST.equals(request.getParameter(OAuth2Constants.Custom.RESPONSE_MODE));
    }

    /**
     * Converts an {@link AuthorizationToken} to a {@link Form}.
     *
     * @param authorizationToken The authorization token to convert.
     * @return A Form of the authorization token.
     */
    Form toForm(AuthorizationToken authorizationToken) {
        return toForm(authorizationToken.getToken());
    }

    /**
     * Converts a {@code Map} into a {@link Form}.
     *
     * @param map The {@code Map} to convert.
     * @return A Form containing the map.
     */
    Form toForm(Map<String, String> map) {
        final Form result = new Form();
        for (final Map.Entry<String, String> entry : map.entrySet()) {
            final Parameter p = new Parameter(entry.getKey(), entry.getValue());
            if (!result.contains(p)) {
                result.add(p);
            }
        }
        return result;
    }
}
