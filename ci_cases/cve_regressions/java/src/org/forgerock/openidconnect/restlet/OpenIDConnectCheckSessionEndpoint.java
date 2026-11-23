package org.forgerock.openidconnect.restlet;

import org.forgerock.oauth2.core.OAuth2Request;
import org.forgerock.oauth2.core.OAuth2RequestFactory;
import org.forgerock.oauth2.core.exceptions.InvalidClientException;
import org.forgerock.oauth2.core.exceptions.NotFoundException;
import org.forgerock.oauth2.core.exceptions.OAuth2Exception;
import org.forgerock.oauth2.core.exceptions.UnauthorizedClientException;
import org.forgerock.oauth2.restlet.ExceptionHandler;
import org.forgerock.oauth2.restlet.OAuth2Representation;
import org.forgerock.oauth2.restlet.OAuth2RestletException;
import org.forgerock.openam.services.baseurl.BaseURLProviderFactory;
import org.forgerock.openidconnect.CheckSession;
import org.restlet.Context;
import org.forgerock.openam.rest.jakarta.servlet.ServletUtils;
import org.restlet.representation.Representation;
import org.restlet.resource.Get;
import org.restlet.resource.Post;
import org.restlet.resource.ServerResource;
import org.restlet.routing.Router;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.HashMap;
import java.util.Map;

import jakarta.inject.Inject;
import jakarta.inject.Named;
import jakarta.servlet.http.HttpServletRequest;

/**
 * Handles requests to the OpenId Connect checkSession endpoint to retrieve the status of OpenId Connect user sessions.
 */
public class OpenIDConnectCheckSessionEndpoint extends ServerResource {
  private final Logger logger = LoggerFactory.getLogger("OAuth2Provider");

  private final OAuth2RequestFactory requestFactory;
  
  private final OAuth2Representation representation;
  
  private final CheckSession checkSession;
  
  private final ExceptionHandler exceptionHandler;
  
  private final Router router;
  
  private final BaseURLProviderFactory baseURLProviderFactory;
  

  /**
   * Constructs a new OpenIDConnectCheckSessionEndpoint.
   *
   * @param requestFactory An instance of the OAuth2RequestFactory.
   * @param representation An instance of the OAuth2Representation.
   * @param checkSession An instance of the CheckSession.
   * @param router An instance of the Router.
   * @param exceptionHandler An instance of the ExceptionHandler.
   * @param baseURLProviderFactory An instance of the BaseURLProviderFactory.
   */
  @Inject
  public OpenIDConnectCheckSessionEndpoint(OAuth2RequestFactory requestFactory, 
    OAuth2Representation representation, CheckSession checkSession, @Named("OAuth2Router") Router router, 
    ExceptionHandler exceptionHandler, BaseURLProviderFactory baseURLProviderFactory) {
    this.requestFactory = requestFactory;
    this.representation = representation;
    this.checkSession = checkSession;
    this.exceptionHandler = exceptionHandler;
    this.router = router;
    this.baseURLProviderFactory = baseURLProviderFactory;
  }
  
  /**
  * Handles GET requests to the OpenId Connect checkSession endpoint to retrieve the status of OpenId Connect user sessions.
  *
  * @return The body to be sent in the response to the user agent.
  * @throws OAuth2RestletException If an error occurs whilst ending the users session.
  */
  @Get
  public Representation checkSession() throws OAuth2RestletException {
    return checkSession(null);
  }
  
  /**
   * Handles POST requests to the OpenId Connect checkSession endpoint.
   *
   * @param entity The entity on the request.
   * @return The body to be sent in the response to the user agent.
   * @throws OAuth2RestletException If a OAuth2 error occurs whilst processing the authorization request.
   */
  @Post
  public Representation checkSession(Representation entity) throws OAuth2RestletException {
    OAuth2Request request = this.requestFactory.create(getRequest());
    
    try {
      return this.representation.getRepresentation(getContext(), request, "checkSession.ftl", getDataModel(request));
    } catch (OAuth2Exception e) {
      throw new OAuth2RestletException(e.getStatusCode(), e.getError(), e.getMessage(), null);
    } 
  }
  
  protected Map<String, Object> getDataModel(OAuth2Request oAuth2Request) throws UnauthorizedClientException, InvalidClientException, NotFoundException {
    // Get the current request
    HttpServletRequest request = ServletUtils.getRequest(oAuth2Request.getRequest());
    String realm = (String)oAuth2Request.getParameter("realm");

    // Get the appropriate values from the CheckSession class
    String cookieName = this.checkSession.getCookieName();
    String clientSessionURI = this.checkSession.getClientSessionURI(request);
    Boolean validSession = Boolean.valueOf(this.checkSession.getValidSession(request));

    // Build the data model for the template
    Map<String, Object> data = new HashMap<>(getRequest().getAttributes());

    data.put("cookie_name", cookieName);
    data.put("client_uri", clientSessionURI);
    data.put("valid_session", validSession.toString());
    data.put("baseUrl", this.baseURLProviderFactory.get(realm).getRootURL(request));
    
    return data;
  }
  
  protected void doCatch(Throwable throwable) {
    this.exceptionHandler.handle(throwable, getResponse());
  }
  
  public Context getContext() {
    return this.router.getContext();
  }
}
