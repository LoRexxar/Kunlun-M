package com.sun.identity.federation.common;

import jakarta.servlet.RequestDispatcher;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.net.URL;

/**
 * Faithful trim of FSUtils.forwardRequest (OpenAM 16.1.3, FSUtils.java:300-390).
 * CVE-2026-123551: same-container target -> RequestDispatcher.forward internal
 * dispatch which skips REQUEST-only security filters, reaching /notifications.
 */
public class FSUtils {

    public static void forwardRequest(
        HttpServletRequest request,
        HttpServletResponse response,
        String url)
    {
        String newUrl = null;
        newUrl = url;

        try {
            URL target = new URL(newUrl);
            String targetHost = target.getHost();
            int targetPort = target.getPort();
            String sourceHost = request.getServerName();
            int sourcePort = request.getServerPort();

            int index = newUrl.indexOf("/openam" + "/");
            if (!(sourceHost.equals(targetHost)) || !(sourcePort == targetPort)
                || !(index > 0)) {
                // not same container -> redirect (open-redirect arm)
                response.sendRedirect(newUrl);
                return;
            } else {
                String resource = newUrl.substring(index + "/openam".length());
                // ForwardPathValidator (16.1.3) only blocks traversal/WEB-INF;
                // a plain in-app path like /notifications is still forwarded.
                RequestDispatcher dispatcher = request.getRequestDispatcher(resource);
                dispatcher.forward(request, response);
            }
        } catch (Exception ex) {
        }
    }
}
