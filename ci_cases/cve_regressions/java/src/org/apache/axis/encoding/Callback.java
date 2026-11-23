package org.apache.axis.encoding;

import org.xml.sax.SAXException;

public interface Callback
{
    public void setValue(Object value, Object hint) throws SAXException;
}
