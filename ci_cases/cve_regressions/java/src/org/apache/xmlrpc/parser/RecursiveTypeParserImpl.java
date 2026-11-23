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

import javax.xml.namespace.QName;

import org.apache.ws.commons.util.NamespaceContextImpl;
import org.apache.xmlrpc.XmlRpcException;
import org.apache.xmlrpc.common.TypeFactory;
import org.apache.xmlrpc.common.XmlRpcExtensionException;
import org.apache.xmlrpc.common.XmlRpcStreamConfig;
import org.apache.xmlrpc.serializer.XmlRpcWriter;
import org.xml.sax.Attributes;
import org.xml.sax.SAXException;
import org.xml.sax.SAXParseException;


/** Abstract base class of a parser, that invokes other type
 * parsers recursively.
 */
public abstract class RecursiveTypeParserImpl extends TypeParserImpl {
	private final NamespaceContextImpl context;
	protected final XmlRpcStreamConfig cfg;
	private final TypeFactory factory;
	private boolean inValueTag;
	private TypeParser typeParser;
    private StringBuffer text = new StringBuffer();

	/** Creates a new instance.
	 * @param pContext The namespace context.
	 * @param pConfig The request or response configuration.
	 * @param pFactory The type factory.
	 */
	protected RecursiveTypeParserImpl(XmlRpcStreamConfig pConfig,
									  NamespaceContextImpl pContext,
									  TypeFactory pFactory) {
		cfg = pConfig;
		context = pContext;
		factory = pFactory;
	}

	/**
	 * Called to start a value tag.
	 * @throws SAXException
	 */
	protected void startValueTag() throws SAXException {
		inValueTag = true;
		text.setLength(0);
		typeParser = null;
	}

	protected abstract void addResult(Object pResult) throws SAXException;

	protected void endValueTag() throws SAXException {
		if (inValueTag) {
			if (typeParser == null) {
				addResult(text.toString());
                text.setLength(0);
			} else {
				typeParser.endDocument();
				try {
					addResult(typeParser.getResult());
				} catch (XmlRpcException e) {
					throw new SAXException(e);
				}
				typeParser = null;
			}
		} else {
			throw new SAXParseException("Invalid state: Not inside value tag.",
										getDocumentLocator());
		}
	}

	public void startDocument() throws SAXException {
		inValueTag = false;
        text.setLength(0);
		typeParser = null;
	}

	public void endElement(String pURI, String pLocalName, String pQName)
			throws SAXException {
		if (inValueTag) {
			if (typeParser == null) {
				throw new SAXParseException("Invalid state: No type parser configured.",
											getDocumentLocator());
			} else {
				typeParser.endElement(pURI, pLocalName, pQName);
			}
		} else {
			throw new SAXParseException("Invalid state: Not inside value tag.",
					getDocumentLocator());
		}
	}

	public void startElement(String pURI, String pLocalName,
							 String pQName, Attributes pAttrs) throws SAXException {
		if (inValueTag) {
			if (typeParser == null) {
				typeParser = factory.getParser(cfg, context, pURI, pLocalName);
				if (typeParser == null) {
					if (XmlRpcWriter.EXTENSIONS_URI.equals(pURI)  &&  !cfg.isEnabledForExtensions()) {
						String msg = "The tag " + new QName(pURI, pLocalName) + " is invalid, if isEnabledForExtensions() == false.";
						throw new SAXParseException(msg, getDocumentLocator(),
													new XmlRpcExtensionException(msg));
					} else {
						throw new SAXParseException("Unknown type: " + new QName(pURI, pLocalName),
													getDocumentLocator());
					}
				}
				typeParser.setDocumentLocator(getDocumentLocator());
				typeParser.startDocument();
				if (text.length() > 0) {
					typeParser.characters(text.toString().toCharArray(), 0, text.length());
                    text.setLength(0);
				}
			}
			typeParser.startElement(pURI, pLocalName, pQName, pAttrs);
		} else {
			throw new SAXParseException("Invalid state: Not inside value tag.",
					getDocumentLocator());
		}
	}

	public void characters(char[] pChars, int pOffset, int pLength) throws SAXException {
		if (typeParser == null) {
			if (inValueTag) {
			    text.append(pChars, pOffset, pLength);
			} else {
				super.characters(pChars, pOffset, pLength);
			}
		} else {
			typeParser.characters(pChars, pOffset, pLength);
		}
	}

	public void ignorableWhitespace(char[] pChars, int pOffset, int pLength) throws SAXException {
		if (typeParser == null) {
			if (inValueTag) {
			    text.append(pChars, pOffset, pLength);
			} else {
				super.ignorableWhitespace(pChars, pOffset, pLength);
			}
		} else {
			typeParser.ignorableWhitespace(pChars, pOffset, pLength);
		}
	}

	public void processingInstruction(String pTarget, String pData) throws SAXException {
		if (typeParser == null) {
			super.processingInstruction(pTarget, pData);
		} else {
			typeParser.processingInstruction(pTarget, pData);
		}
	}

	public void skippedEntity(String pEntity) throws SAXException {
		if (typeParser == null) {
			super.skippedEntity(pEntity);
		} else {
			typeParser.skippedEntity(pEntity);
		}
	}

	public void startPrefixMapping(String pPrefix, String pURI) throws SAXException {
		if (typeParser == null) {
			super.startPrefixMapping(pPrefix, pURI);
		} else {
			context.startPrefixMapping(pPrefix, pURI);
		}
	}

	public void endPrefixMapping(String pPrefix) throws SAXException {
		if (typeParser == null) {
			super.endPrefixMapping(pPrefix);
		} else {
			context.endPrefixMapping(pPrefix);
		}
	}
}
