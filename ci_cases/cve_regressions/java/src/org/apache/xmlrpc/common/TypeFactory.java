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

import org.apache.ws.commons.util.NamespaceContextImpl;
import org.apache.xmlrpc.parser.TypeParser;
import org.apache.xmlrpc.serializer.TypeSerializer;
import org.xml.sax.SAXException;


/** A type factory creates serializers or handlers, based on the object
 * type.
 */
public interface TypeFactory {
	/** Creates a serializer for the object <code>pObject</code>.
	 * @param pConfig The request configuration.
	 * @param pObject The object being serialized.
	 * @return A serializer for <code>pObject</code>.
	 * @throws SAXException Creating the serializer failed.
	 */
	TypeSerializer getSerializer(XmlRpcStreamConfig pConfig, Object pObject) throws SAXException;

	/** Creates a parser for a parameter or result object.
	 * @param pConfig The request configuration.
	 * @param pContext A namespace context, for looking up prefix mappings.
	 * @param pURI The namespace URI of the element containing the parameter or result.
	 * @param pLocalName The local name of the element containing the parameter or result.
	 * @return The created parser.
	 */
	TypeParser getParser(XmlRpcStreamConfig pConfig, NamespaceContextImpl pContext, String pURI, String pLocalName);
}
