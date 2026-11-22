/*
 * Licensed to the Apache Software Foundation (ASF) under one
 * or more contributor license agreements.  See the NOTICE file
 * distributed with this work for additional information
 * regarding copyright ownership.  The ASF licenses this file
 * to you under the Apache License, Version 2.0 (the
 * "License"); you may not use this file except in compliance
 * with the License.  You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.    
 */
package org.apache.xmlrpc.common;

import java.io.Serializable;
import java.math.BigDecimal;
import java.math.BigInteger;
import java.util.Calendar;
import java.util.Date;
import java.util.List;
import java.util.Map;
import java.util.TimeZone;

import org.apache.ws.commons.util.NamespaceContextImpl;
import org.apache.xmlrpc.parser.BigDecimalParser;
import org.apache.xmlrpc.parser.BigIntegerParser;
import org.apache.xmlrpc.parser.BooleanParser;
import org.apache.xmlrpc.parser.ByteArrayParser;
import org.apache.xmlrpc.parser.CalendarParser;
import org.apache.xmlrpc.parser.DateParser;
import org.apache.xmlrpc.parser.DoubleParser;
import org.apache.xmlrpc.parser.FloatParser;
import org.apache.xmlrpc.parser.I1Parser;
import org.apache.xmlrpc.parser.I2Parser;
import org.apache.xmlrpc.parser.I4Parser;
import org.apache.xmlrpc.parser.I8Parser;
import org.apache.xmlrpc.parser.MapParser;
import org.apache.xmlrpc.parser.NodeParser;
import org.apache.xmlrpc.parser.NullParser;
import org.apache.xmlrpc.parser.ObjectArrayParser;
import org.apache.xmlrpc.parser.SerializableParser;
import org.apache.xmlrpc.parser.StringParser;
import org.apache.xmlrpc.parser.TypeParser;
import org.apache.xmlrpc.serializer.BigDecimalSerializer;
import org.apache.xmlrpc.serializer.BigIntegerSerializer;
import org.apache.xmlrpc.serializer.BooleanSerializer;
import org.apache.xmlrpc.serializer.ByteArraySerializer;
import org.apache.xmlrpc.serializer.CalendarSerializer;
import org.apache.xmlrpc.serializer.DateSerializer;
import org.apache.xmlrpc.serializer.DoubleSerializer;
import org.apache.xmlrpc.serializer.FloatSerializer;
import org.apache.xmlrpc.serializer.I1Serializer;
import org.apache.xmlrpc.serializer.I2Serializer;
import org.apache.xmlrpc.serializer.I4Serializer;
import org.apache.xmlrpc.serializer.I8Serializer;
import org.apache.xmlrpc.serializer.ListSerializer;
import org.apache.xmlrpc.serializer.MapSerializer;
import org.apache.xmlrpc.serializer.NodeSerializer;
import org.apache.xmlrpc.serializer.NullSerializer;
import org.apache.xmlrpc.serializer.ObjectArraySerializer;
import org.apache.xmlrpc.serializer.SerializableSerializer;
import org.apache.xmlrpc.serializer.StringSerializer;
import org.apache.xmlrpc.serializer.TypeSerializer;
import org.apache.xmlrpc.serializer.XmlRpcWriter;
import org.apache.xmlrpc.util.XmlRpcDateTimeDateFormat;
import org.w3c.dom.Node;
import org.xml.sax.SAXException;


/** Default implementation of a type factory.
 */
public class TypeFactoryImpl implements TypeFactory {
	private static final TypeSerializer NULL_SERIALIZER = new NullSerializer();
	private static final TypeSerializer STRING_SERIALIZER = new StringSerializer();
	private static final TypeSerializer I4_SERIALIZER = new I4Serializer();
	private static final TypeSerializer BOOLEAN_SERIALIZER = new BooleanSerializer();
	private static final TypeSerializer DOUBLE_SERIALIZER = new DoubleSerializer();
	private static final TypeSerializer BYTE_SERIALIZER = new I1Serializer();
	private static final TypeSerializer SHORT_SERIALIZER = new I2Serializer();
	private static final TypeSerializer LONG_SERIALIZER = new I8Serializer();
	private static final TypeSerializer FLOAT_SERIALIZER = new FloatSerializer();
	private static final TypeSerializer NODE_SERIALIZER = new NodeSerializer();
    private static final TypeSerializer SERIALIZABLE_SERIALIZER = new SerializableSerializer();
    private static final TypeSerializer BIGDECIMAL_SERIALIZER = new BigDecimalSerializer();
    private static final TypeSerializer BIGINTEGER_SERIALIZER = new BigIntegerSerializer();
    private static final TypeSerializer CALENDAR_SERIALIZER = new CalendarSerializer();

	private final XmlRpcController controller;
    private DateSerializer dateSerializer;

	/** Creates a new instance.
	 * @param pController The controller, which operates the type factory.
	 */
	public TypeFactoryImpl(XmlRpcController pController) {
		controller = pController;
	}

	/** Returns the controller, which operates the type factory.
	 * @return The controller, an instance of
	 * {@link org.apache.xmlrpc.client.XmlRpcClient},
	 * or {@link org.apache.xmlrpc.server.XmlRpcServer}.
	 */
	public XmlRpcController getController() {
		return controller;
	}

	public TypeSerializer getSerializer(XmlRpcStreamConfig pConfig, Object pObject) throws SAXException {
		if (pObject == null) {
			if (pConfig.isEnabledForExtensions()) {
				return NULL_SERIALIZER;
			} else {
				throw new SAXException(new XmlRpcExtensionException("Null values aren't supported, if isEnabledForExtensions() == false"));
			}
		} else if (pObject instanceof String) {
			return STRING_SERIALIZER;
		} else if (pObject instanceof Byte) {
			if (pConfig.isEnabledForExtensions()) {
				return BYTE_SERIALIZER;
			} else {
				throw new SAXException(new XmlRpcExtensionException("Byte values aren't supported, if isEnabledForExtensions() == false"));
			}
		} else if (pObject instanceof Short) {
			if (pConfig.isEnabledForExtensions()) {
				return SHORT_SERIALIZER;
			} else {
				throw new SAXException(new XmlRpcExtensionException("Short values aren't supported, if isEnabledForExtensions() == false"));
			}
		} else if (pObject instanceof Integer) {
			return I4_SERIALIZER;
		} else if (pObject instanceof Long) {
			if (pConfig.isEnabledForExtensions()) {
				return LONG_SERIALIZER;
			} else {
				throw new SAXException(new XmlRpcExtensionException("Long values aren't supported, if isEnabledForExtensions() == false"));
			}
		} else if (pObject instanceof Boolean) {
			return BOOLEAN_SERIALIZER;
		} else if (pObject instanceof Float) {
			if (pConfig.isEnabledForExtensions()) {
				return FLOAT_SERIALIZER;
			} else {
				throw new SAXException(new XmlRpcExtensionException("Float values aren't supported, if isEnabledForExtensions() == false"));
			}
		} else if (pObject instanceof Double) {
			return DOUBLE_SERIALIZER;
		} else if (pObject instanceof Calendar) {
            if (pConfig.isEnabledForExtensions()) {
                return CALENDAR_SERIALIZER;
            } else {
                throw new SAXException(new XmlRpcExtensionException("Calendar values aren't supported, if isEnabledForExtensions() == false"));
            }
        } else if (pObject instanceof Date) {
            if (dateSerializer == null) {
                dateSerializer = new DateSerializer(new XmlRpcDateTimeDateFormat(){
                    private static final long serialVersionUID = 24345909123324234L;
                    protected TimeZone getTimeZone() {
                        return controller.getConfig().getTimeZone();
                    }
                });
            }
            return dateSerializer;
    	} else if (pObject instanceof byte[]) {
			return new ByteArraySerializer();
		} else if (pObject instanceof Object[]) {
			return new ObjectArraySerializer(this, pConfig);
		} else if (pObject instanceof List) {
			return new ListSerializer(this, pConfig);
		} else if (pObject instanceof Map) {
			return new MapSerializer(this, pConfig);
		} else if (pObject instanceof Node) {
			if (pConfig.isEnabledForExtensions()) {
				return NODE_SERIALIZER;
			} else {
				throw new SAXException(new XmlRpcExtensionException("DOM nodes aren't supported, if isEnabledForExtensions() == false"));
			}
        } else if (pObject instanceof BigInteger) {
            if (pConfig.isEnabledForExtensions()) {
                return BIGINTEGER_SERIALIZER;
            } else {
                throw new SAXException(new XmlRpcExtensionException("BigInteger values aren't supported, if isEnabledForExtensions() == false"));
            }
        } else if (pObject instanceof BigDecimal) {
            if (pConfig.isEnabledForExtensions()) {
                return BIGDECIMAL_SERIALIZER;
            } else {
                throw new SAXException(new XmlRpcExtensionException("BigDecimal values aren't supported, if isEnabledForExtensions() == false"));
            }
		} else if (pObject instanceof Serializable) {
			if (pConfig.isEnabledForExtensions()) {
				return SERIALIZABLE_SERIALIZER;
			} else {
				throw new SAXException(new XmlRpcExtensionException("Serializable objects aren't supported, if isEnabledForExtensions() == false"));
			}
		} else {
			return null;
		}
	}

	public TypeParser getParser(XmlRpcStreamConfig pConfig, NamespaceContextImpl pContext, String pURI, String pLocalName) {
		if (XmlRpcWriter.EXTENSIONS_URI.equals(pURI)) {
			if (!pConfig.isEnabledForExtensions()) {
				return null;
			}
			if (NullSerializer.NIL_TAG.equals(pLocalName)) {
				return new NullParser();
			} else if (I1Serializer.I1_TAG.equals(pLocalName)) {
				return new I1Parser();
			} else if (I2Serializer.I2_TAG.equals(pLocalName)) {
				return new I2Parser();
			} else if (I8Serializer.I8_TAG.equals(pLocalName)) {
				return new I8Parser();
			} else if (FloatSerializer.FLOAT_TAG.equals(pLocalName)) {
				return new FloatParser();
            } else if (NodeSerializer.DOM_TAG.equals(pLocalName)) {
                return new NodeParser();
            } else if (BigDecimalSerializer.BIGDECIMAL_TAG.equals(pLocalName)) {
                return new BigDecimalParser();
            } else if (BigIntegerSerializer.BIGINTEGER_TAG.equals(pLocalName)) {
                return new BigIntegerParser();
			} else if (SerializableSerializer.SERIALIZABLE_TAG.equals(pLocalName)) {
				return new SerializableParser();
			} else if (CalendarSerializer.CALENDAR_TAG.equals(pLocalName)) {
			    return new CalendarParser();
            }
		} else if ("".equals(pURI)) {
			if (I4Serializer.INT_TAG.equals(pLocalName)  ||  I4Serializer.I4_TAG.equals(pLocalName)) {
				return new I4Parser();
			} else if (BooleanSerializer.BOOLEAN_TAG.equals(pLocalName)) {
				return new BooleanParser();
			} else if (DoubleSerializer.DOUBLE_TAG.equals(pLocalName)) {
				return new DoubleParser();
			} else if (DateSerializer.DATE_TAG.equals(pLocalName)) {
				return new DateParser(new XmlRpcDateTimeDateFormat(){
                    private static final long serialVersionUID = 7585237706442299067L;
                    protected TimeZone getTimeZone() {
                        return controller.getConfig().getTimeZone();
                    }
                });
			} else if (ObjectArraySerializer.ARRAY_TAG.equals(pLocalName)) {
				return new ObjectArrayParser(pConfig, pContext, this);
			} else if (MapSerializer.STRUCT_TAG.equals(pLocalName)) {
				return new MapParser(pConfig, pContext, this);
			} else if (ByteArraySerializer.BASE_64_TAG.equals(pLocalName)) {
				return new ByteArrayParser();
			} else if (StringSerializer.STRING_TAG.equals(pLocalName)) {
				return new StringParser();
			}
		}
		return null;
	}
}
