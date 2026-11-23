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
package org.apache.xmlrpc.parser;

import java.util.ArrayList;
import java.util.List;

import javax.xml.namespace.QName;

import org.apache.ws.commons.util.NamespaceContextImpl;
import org.apache.xmlrpc.common.TypeFactory;
import org.apache.xmlrpc.common.XmlRpcStreamConfig;
import org.xml.sax.Attributes;
import org.xml.sax.SAXException;
import org.xml.sax.SAXParseException;


/** A SAX parser for an {@link org.apache.xmlrpc.client.XmlRpcClient}'s
 * request.
 */
public class XmlRpcRequestParser extends RecursiveTypeParserImpl {
	private int level;
	private boolean inMethodName;
	private String methodName;
	private List params;

	/** Creates a new instance, which parses a clients request.
	 * @param pConfig The client configuration.
	 * @param pTypeFactory The type factory.
	 */
	public XmlRpcRequestParser(XmlRpcStreamConfig pConfig, TypeFactory pTypeFactory) {
		super(pConfig, new NamespaceContextImpl(), pTypeFactory);
	}

	protected void addResult(Object pResult) {
		params.add(pResult);
	}

	public void startDocument() throws SAXException {
		super.startDocument();
		level = 0;
		inMethodName = false;
		methodName = null;
		params = null;
	}


	public void characters(char[] pChars, int pOffset, int pLength) throws SAXException {
		if (inMethodName) {
			String s = new String(pChars, pOffset, pLength);
			methodName = methodName == null ? s : methodName + s;
		} else {
			super.characters(pChars, pOffset, pLength);
		}
	}

	public void startElement(String pURI, String pLocalName, String pQName,
							 Attributes pAttrs) throws SAXException {
		switch (level++) {
			case 0:
				if (!"".equals(pURI)  ||  !"methodCall".equals(pLocalName)) {
					throw new SAXParseException("Expected root element 'methodCall', got "
							+ new QName(pURI, pLocalName),
							getDocumentLocator());
				}
				break;
			case 1:
				if (methodName == null) {
					if ("".equals(pURI)  &&  "methodName".equals(pLocalName)) {
						inMethodName = true;
					} else {
						throw new SAXParseException("Expected methodName element, got "
													+ new QName(pURI, pLocalName),
													getDocumentLocator());
					}
				} else if (params == null) {
					if ("".equals(pURI)  &&  "params".equals(pLocalName)) {
						params = new ArrayList();
					} else {
						throw new SAXParseException("Expected params element, got "
													+ new QName(pURI, pLocalName),
													getDocumentLocator());
					}
				} else {
					throw new SAXParseException("Expected /methodCall, got "
												+ new QName(pURI, pLocalName),
												getDocumentLocator());
				}
				break;
			case 2:
				if (!"".equals(pURI)  ||  !"param".equals(pLocalName)) {
					throw new SAXParseException("Expected param element, got "
												+ new QName(pURI, pLocalName),
												getDocumentLocator());
				}
				break;
			case 3:
				if (!"".equals(pURI)  ||  !"value".equals(pLocalName)) {
					throw new SAXParseException("Expected value element, got "
												+ new QName(pURI, pLocalName),
												getDocumentLocator());
				}
				startValueTag();
				break;
			default:
				super.startElement(pURI, pLocalName, pQName, pAttrs);
				break;
		}
	}

	public void endElement(String pURI, String pLocalName, String pQName) throws SAXException {
		switch(--level) {
			case 0:
				break;
			case 1:
				if (inMethodName) {
					if ("".equals(pURI)  &&  "methodName".equals(pLocalName)) {
						if (methodName == null) {
							methodName = "";
						}
					} else {
						throw new SAXParseException("Expected /methodName, got "
													+ new QName(pURI, pLocalName),
													getDocumentLocator());
					}
					inMethodName = false;
				} else if (!"".equals(pURI)  ||  !"params".equals(pLocalName)) {
					throw new SAXParseException("Expected /params, got "
							+ new QName(pURI, pLocalName),
							getDocumentLocator());
				}
				break;
			case 2:
				if (!"".equals(pURI)  ||  !"param".equals(pLocalName)) {
					throw new SAXParseException("Expected /param, got "
												+ new QName(pURI, pLocalName),
												getDocumentLocator());
				}
				break;
			case 3:
				if (!"".equals(pURI)  ||  !"value".equals(pLocalName)) {
					throw new SAXParseException("Expected /value, got "
												+ new QName(pURI, pLocalName),
												getDocumentLocator());
				}
				endValueTag();
				break;
			default:
				super.endElement(pURI, pLocalName, pQName);
				break;
		}
	}

	/** Returns the method name being invoked.
	 * @return Requested method name.
	 */
	public String getMethodName() { return methodName; }
	/** Returns the parameter list.
	 * @return Parameter list.
	 */
	public List getParams() { return params; }
}
