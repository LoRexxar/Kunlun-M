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
package org.apache.xmlrpc.webserver;

import java.io.IOException;
import java.lang.reflect.InvocationTargetException;
import java.net.URL;
import java.util.Enumeration;

import javax.servlet.ServletConfig;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.apache.xmlrpc.XmlRpcConfig;
import org.apache.xmlrpc.XmlRpcException;
import org.apache.xmlrpc.common.TypeConverterFactory;
import org.apache.xmlrpc.server.AbstractReflectiveHandlerMapping;
import org.apache.xmlrpc.server.PropertyHandlerMapping;
import org.apache.xmlrpc.server.RequestProcessorFactoryFactory;
import org.apache.xmlrpc.server.XmlRpcHandlerMapping;
import org.apache.xmlrpc.server.XmlRpcServer;
import org.apache.xmlrpc.util.ReflectionUtil;


/** <p>A default servlet implementation The typical use would
 * be to derive a subclass, which is overwriting at least the
 * method {@link #newXmlRpcHandlerMapping()}.</p>
 * <p>The servlet accepts the following init parameters:
 *   <table border="1">
 *     <tr><th>Name</th><th>Description</th></tr>
 *     <tr><td>enabledForExtensions</td><td>Sets the value
 *       {@link XmlRpcConfig#isEnabledForExtensions()}
 *       to true.</td></tr>
 *   </table>
 * </p>
 */
public class XmlRpcServlet extends HttpServlet {
	private static final long serialVersionUID = 2348768267234L;
	private static final Log log = LogFactory.getLog(XmlRpcServlet.class);
    private XmlRpcServletServer server;
    private AbstractReflectiveHandlerMapping.AuthenticationHandler authenticationHandler;
    private RequestProcessorFactoryFactory requestProcessorFactoryFactory;
    private TypeConverterFactory typeConverterFactory;

	/** Returns the servlets instance of {@link XmlRpcServletServer}. 
	 * @return The configurable instance of {@link XmlRpcServletServer}.
	 */
	public XmlRpcServletServer getXmlRpcServletServer() {
		return server;
	}

    private void handleInitParameters(ServletConfig pConfig) throws ServletException {
        for (Enumeration en = pConfig.getInitParameterNames();  en.hasMoreElements();  ) {
            String name = (String) en.nextElement();
            String value = pConfig.getInitParameter(name);
            try {
                if (!ReflectionUtil.setProperty(this, name, value)
                    &&  !ReflectionUtil.setProperty(server, name, value)
                    &&  !ReflectionUtil.setProperty(server.getConfig(), name, value)) {
                    throw new ServletException("Unknown init parameter " + name);
                }
            } catch (IllegalAccessException e) {
                throw new ServletException("Illegal access to instance of " + server.getClass().getName()
                        + " while setting property " + name + ": " + e.getMessage(), e);
            } catch (InvocationTargetException e) {
                Throwable t = e.getTargetException();
                throw new ServletException("Failed to invoke setter for property " + name
                        + " on instance of " + server.getClass().getName()
                        + ": " + t.getMessage(), t);
            }
        }
    }

	public void init(ServletConfig pConfig) throws ServletException {
		super.init(pConfig);
		try {
            server = newXmlRpcServer(pConfig);
            handleInitParameters(pConfig);
			server.setHandlerMapping(newXmlRpcHandlerMapping());
        } catch (XmlRpcException e) {
			try {
				log("Failed to create XmlRpcServer: " + e.getMessage(), e);
			} catch (Throwable ignore) {
			}
			throw new ServletException(e);
		}
	}

	/** Sets the servlets {@link AbstractReflectiveHandlerMapping.AuthenticationHandler}.
	 */
	public void setAuthenticationHandler(AbstractReflectiveHandlerMapping.AuthenticationHandler pHandler) {
	    authenticationHandler = pHandler;
	}

	/** Returns the servlets {@link AbstractReflectiveHandlerMapping.AuthenticationHandler}.
	 */
	public AbstractReflectiveHandlerMapping.AuthenticationHandler getAuthenticationHandler() {
	    return authenticationHandler;
	}

	/** Sets the servlets {@link RequestProcessorFactoryFactory}.
	 */
	public void setRequestProcessorFactoryFactory(RequestProcessorFactoryFactory pFactory) {
        requestProcessorFactoryFactory = pFactory;
	}

	/** Returns the servlets {@link RequestProcessorFactoryFactory}.
	 */
	public RequestProcessorFactoryFactory getRequestProcessorFactoryFactory() {
        return requestProcessorFactoryFactory;
	}

	/** Sets the servlets {@link TypeConverterFactory}.
	 */
	public void setTypeConverterFactory(TypeConverterFactory pFactory) {
	    typeConverterFactory = pFactory;
	}

    /** Returns the servlets {@link TypeConverterFactory}.
     */
    public TypeConverterFactory getTypeConverterFactory() {
        return typeConverterFactory;
    }

    /** Creates a new instance of {@link XmlRpcServer},
	 * which is being used to process the requests. The default implementation
	 * will simply invoke <code>new {@link XmlRpcServer}.
	 * @param pConfig The servlets configuration.
	 * @throws XmlRpcException
	 */
	protected XmlRpcServletServer newXmlRpcServer(ServletConfig pConfig)
			throws XmlRpcException {
		return new XmlRpcServletServer();
	}

	/** Creates a new handler mapping. The default implementation loads
	 * a property file from the resource
	 * <code>org/apache/xmlrpc/webserver/XmlRpcServlet.properties</code>
	 */
	protected XmlRpcHandlerMapping newXmlRpcHandlerMapping() throws XmlRpcException {
		URL url = XmlRpcServlet.class.getResource("XmlRpcServlet.properties");
		if (url == null) {
			throw new XmlRpcException("Failed to locate resource XmlRpcServlet.properties");
		}
		try {
			return newPropertyHandlerMapping(url);
		} catch (IOException e) {
			throw new XmlRpcException("Failed to load resource " + url + ": " + e.getMessage(), e);
		}
	}

	/** Creates a new instance of {@link PropertyHandlerMapping} by
	 * loading the property file from the given URL. Called from
	 * {@link #newXmlRpcHandlerMapping()}.
	 */
	protected PropertyHandlerMapping newPropertyHandlerMapping(URL url) throws IOException, XmlRpcException {
        PropertyHandlerMapping mapping = new PropertyHandlerMapping();
        mapping.setAuthenticationHandler(authenticationHandler);
        if (requestProcessorFactoryFactory != null) {
            mapping.setRequestProcessorFactoryFactory(requestProcessorFactoryFactory);
        }
        if (typeConverterFactory != null) {
            mapping.setTypeConverterFactory(typeConverterFactory);
        } else {
            mapping.setTypeConverterFactory(server.getTypeConverterFactory());
        }
        mapping.setVoidMethodEnabled(server.getConfig().isEnabledForExtensions());
        mapping.load(Thread.currentThread().getContextClassLoader(), url);
        return mapping;
	}

	/** Creates a new instance of {@link org.apache.xmlrpc.webserver.RequestData}
	 * for the request.
	 */
	public void doPost(HttpServletRequest pRequest, HttpServletResponse pResponse) throws IOException, ServletException {
		server.execute(pRequest, pResponse);
	}

    public void log(String pMessage, Throwable pThrowable) {
        server.getErrorLogger().log(pMessage, pThrowable);
    }

    public void log(String pMessage) {
        log.info(pMessage);
    }
}
