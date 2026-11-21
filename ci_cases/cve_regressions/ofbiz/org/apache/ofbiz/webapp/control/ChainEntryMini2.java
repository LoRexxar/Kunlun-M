package org.apache.ofbiz.webapp.control;

import java.util.HashMap;
import java.util.Map;
import jakarta.servlet.http.HttpServlet;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

import org.apache.ofbiz.base.util.UtilHttp;
import org.apache.ofbiz.widget.model.ScreenFactory;

public class ChainEntryMini2 extends HttpServlet {

    protected void doGet(HttpServletRequest request, HttpServletResponse response) {
        try {
            Map<String, Object> context = new HashMap<>();
            context.putAll(request.getParameterMap());
            String location = (String) context.get("mainDecoratorLocation");
            ScreenFactory.renderReferencedScreen("CommonLoginDecorator", location, null,
                    new java.io.StringWriter(), context, null);
        } catch (Exception e) {
        }
    }
}
