package org.apache.ofbiz.base.util;

import java.util.HashMap;
import java.util.Map;
import jakarta.servlet.http.HttpServletRequest;

public class UtilHttp {

    public static Map<String, Object> getCombinedMap(HttpServletRequest request) {
        Map<String, Object> combinedMap = new HashMap<>();
        combinedMap.putAll(request.getParameterMap());
        return combinedMap;
    }
}
