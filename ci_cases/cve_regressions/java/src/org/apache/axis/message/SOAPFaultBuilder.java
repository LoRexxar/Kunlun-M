package org.apache.axis.message;

/**
 * Minimal repro of CVE-2026-90436 reflective construction sinks.
 */
public class SOAPFaultBuilder
{
    protected Class faultClass;
    protected Object faultData;

    public void setFaultClass(Class faultClass) {
        this.faultClass = faultClass;
    }

    public void setFaultData(Object data) {
        faultData = data;
        createFault();
    }

    private void createFault() {
        Object f = null;

        if (faultClass != null) {
            if (faultData != null) {
                // We need to create the exception,
                // passing the data to the constructor.
                try {
                    Class argClass = faultData.getClass();
                    java.lang.reflect.Constructor con =
                            faultClass.getConstructor(
                                    new Class[] { argClass });
                    f = con.newInstance(new Object[] { faultData });
                } catch(Exception e){
                    // fall through and use a plain AxisFault
                }
            }
            // this is to support the <exceptionName> detail
            f = faultClass.newInstance();
            Object[] args = { f };
        }
    }
}
