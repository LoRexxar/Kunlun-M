package org.apache.axis.message;

import org.xml.sax.SAXException;

public abstract class SOAPHandler
{
    public SOAPHandler onStartChild(String namespace,
                                    String name,
                                    String prefix,
                                    org.xml.sax.Attributes attributes,
                                    Object context)
        throws SAXException
    {
        return null;
    }
}
