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

import java.io.ByteArrayOutputStream;
import java.io.IOException;

import javax.xml.namespace.QName;

import org.apache.ws.commons.util.Base64;
import org.xml.sax.Attributes;
import org.xml.sax.SAXException;
import org.xml.sax.SAXParseException;


/** A parser for base64 elements.
 */
public class ByteArrayParser extends TypeParserImpl {
	private int level;
	private ByteArrayOutputStream baos;
	private Base64.Decoder decoder;

	public void startDocument() throws SAXException {
		level = 0;
	}

	public void characters(char[] pChars, int pStart, int pLength) throws SAXException {
		if (baos == null) {
			if (!isEmpty(pChars, pStart, pLength)) {
				throw new SAXParseException("Unexpected non-whitespace characters",
											getDocumentLocator());
			}
		} else {
			try {
				decoder.write(pChars, pStart, pLength);
			} catch (IOException e) {
				throw new SAXParseException("Failed to decode base64 stream.", getDocumentLocator(), e);
			}
		}
	}

	public void endElement(String pURI, String pLocalName, String pQName) throws SAXException {
		if (--level == 0) {
			try {
				decoder.flush();
			} catch (IOException e) {
				throw new SAXParseException("Failed to decode base64 stream.", getDocumentLocator(), e);
			}
			setResult(baos.toByteArray());
		} else {
			throw new SAXParseException("Unexpected end tag in atomic element: "
										+ new QName(pURI, pLocalName),
										getDocumentLocator());
		}
	}

	public void startElement(String pURI, String pLocalName, String pQName, Attributes pAttrs) throws SAXException {
		if (level++ == 0) {
			baos = new ByteArrayOutputStream();
			decoder = new Base64.Decoder(1024){
				protected void writeBuffer(byte[] pBytes, int pOffset, int pLen) throws IOException {
					baos.write(pBytes, pOffset, pLen);
				}
			};
		} else {
			throw new SAXParseException("Unexpected start tag in atomic element: "
										+ new QName(pURI, pLocalName),
										getDocumentLocator());
		}
	}
}
