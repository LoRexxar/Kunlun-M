package com.sun.identity.federation.login;

import com.sun.identity.federation.common.FSUtils;
import com.sun.identity.federation.common.IFSConstants;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

/**
 * Faithful trim of FSFederationHandler (OpenAM 16.1.3, lines 74-80).
 * Unauthenticated Liberty ID-FF endpoint entry: RelayState request parameter
 * flows straight into FSUtils.forwardRequest.
 */
public class FSFederationHandler {

    public void process(HttpServletRequest request, HttpServletResponse response) {
        try {
            String lrURL = request.getParameter(IFSConstants.LRURL);
            if (lrURL != null) {
                FSUtils.forwardRequest(request, response, lrURL);
            } else {
                FSUtils.forwardRequest(request, response, "/FederationError.jsp");
            }
        } catch (Exception e) {
        }
    }
}
