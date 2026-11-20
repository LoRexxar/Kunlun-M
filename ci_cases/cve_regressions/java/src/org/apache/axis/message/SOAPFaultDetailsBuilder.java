package org.apache.axis.message;

import org.apache.axis.encoding.Callback;
import org.apache.axis.utils.ClassUtils;

/**
 * Handle deserializing fault details (minimal repro of CVE-2026-90436).
 */
public class SOAPFaultDetailsBuilder extends SOAPHandler implements Callback
{
    protected SOAPFaultBuilder builder;

    public SOAPFaultDetailsBuilder(SOAPFaultBuilder builder) {
        this.builder = builder;
    }

    public SOAPHandler onStartChild(String namespace,
                                    String name,
                                    String prefix,
                                    org.xml.sax.Attributes attributes,
                                    Object context)
    {
        // Look for <exceptionName> element and create a class
        // with that name - this is Axis specific
        if (name.equals("exceptionName")) {
            // Set up deser of exception name string
            Object dser = context; // placeholder for deserializer lookup
            return this;
        }

        // register callback for the data
        return null;
    }

    /*
     * Defined by Callback.
     * This method gets control when the callback is invoked.
     */
    public void setValue(Object value, Object hint)
    {
        if ("faultData".equals(hint)) {
            builder.setFaultData(value);
        } else if ("exceptionName".equals(hint)) {
            String faultClassName = (String) value;
            try {
                Class faultClass = ClassUtils.forName(faultClassName);
                builder.setFaultClass(faultClass);
            } catch (ClassNotFoundException e) {
                // Just create an AxisFault, no custom exception
            }
        }

    }
}
