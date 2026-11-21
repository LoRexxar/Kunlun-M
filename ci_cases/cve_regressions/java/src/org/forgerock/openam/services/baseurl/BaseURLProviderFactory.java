/*
 * The contents of this file are subject to the terms of the Common Development and
 * Distribution License (the License). You may not use this file except in compliance with the
 * License.
 *
 * You can obtain a copy of the License at legal/CDDLv1.0.txt. See the License for the
 * specific language governing permission and limitations under the License.
 *
 * When distributing Covered Software, include this CDDL Header Notice in each file and include
 * the License file at legal/CDDLv1.0.txt. If applicable, add the following below the CDDL
 * Header, with the fields enclosed by brackets [] replaced by your own identifying
 * information: "Portions copyright [year] [name of copyright owner]".
 *
 * Copyright 2015-2016 ForgeRock AS.
 * Portions copyright 2025 3A Systems LLC.
 */

package org.forgerock.openam.services.baseurl;

import com.iplanet.sso.SSOException;
import com.iplanet.sso.SSOToken;
import com.sun.identity.security.AdminTokenAction;
import com.sun.identity.shared.debug.Debug;
import com.sun.identity.sm.DNMapper;
import com.sun.identity.sm.SMSException;
import com.sun.identity.sm.ServiceConfigManager;
import com.sun.identity.sm.ServiceListener;
import java.security.AccessController;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import jakarta.inject.Inject;
import jakarta.inject.Named;
import jakarta.inject.Singleton;
import jakarta.servlet.ServletContext;

import org.forgerock.openam.core.CoreWrapper;
import org.forgerock.openam.core.guice.ServletContextCache;
import org.forgerock.openam.utils.OpenAMSettingsImpl;

/**
 * A factory for instances of {@link BaseURLProvider}
 */
@Singleton
public class BaseURLProviderFactory {

    private static final String SERVICE_NAME = "amRealmBaseURL";
    private static final String SERVICE_VERSION = "1.0";
    private static final String PROVIDER_TYPE = "base-url-source";
    private static final String CONTEXT_PATH = "base-url-context-path";

    private final ServletContext servletContext;

    private final Debug debug = Debug.getInstance("amBaseURL");
    private final Map<String, BaseURLProvider> providers = new ConcurrentHashMap<String, BaseURLProvider>();
    private final CoreWrapper coreWrapper;

    @Inject
    public BaseURLProviderFactory(@Named(ServletContextCache.CONTEXT_REFERENCE) ServletContext servletContext,
            CoreWrapper coreWrapper) {
        this.servletContext = servletContext;
        this.coreWrapper = coreWrapper;
        addListener();
    }

    /**
     * Get the BaseURLProvider for a realm.
     *
     * @param realm The realm.
     * @return The BaseURLProvider.
     */
    public BaseURLProvider get(String realm) {
        String realmDN = DNMapper.orgNameToDN(realm);
        BaseURLProvider cached = providers.get(realmDN);
        if (cached != null) {
            return cached;
        }
        return create(realmDN);
    }

    private synchronized BaseURLProvider create(String realmDN) {

        if (!providers.containsKey(realmDN)) {
            debug.message("Creating base URL provider for realm: {}", realmDN);
            OpenAMSettingsImpl settings = new OpenAMSettingsImpl(SERVICE_NAME, SERVICE_VERSION);
            try {
                BaseURLProvider provider;

                if (settings.hasConfig(realmDN)) {
                    ProviderType providerType = ProviderType.valueOf(settings.getStringSetting(realmDN, PROVIDER_TYPE));
                    provider = providerType.getProvider();
                    provider.init(settings, realmDN);
                    provider.setContextPath(settings.getStringSetting(realmDN, CONTEXT_PATH));
                } else {
                    provider = new RequestValuesBaseURLProvider();
                    provider.setContextPath(servletContext.getContextPath());
                }
                provider.setCoreWrapper(coreWrapper);

                providers.put(realmDN, provider);
            } catch (SMSException | SSOException e) {
                debug.error("Unable to access BaseURL config for realm {}", realmDN, e);
                throw new IllegalStateException(e);
            }
        }
        return providers.get(realmDN);
    }

    private void addListener() {
        try {
            final SSOToken token = AccessController.doPrivileged(AdminTokenAction.getInstance());
            final ServiceConfigManager serviceConfigManager = new ServiceConfigManager(token, SERVICE_NAME,
                    SERVICE_VERSION);
            if (serviceConfigManager.addListener(new SettingsChangeListener()) == null) {
                debug.error("Could not add listener. Base URLs will not be dynamically updated");
            }
        } catch (SMSException e) {
            debug.error("Unable to construct ServiceConfigManager", e);
            throw new IllegalStateException(e);
        } catch (SSOException e) {
            debug.error("Unable to construct ServiceConfigManager", e);
            throw new IllegalStateException(e);
        }
    }

    /**
     * ServiceListener implementation to clear cache when it changes.
     */
    private final class SettingsChangeListener implements ServiceListener {

        public void schemaChanged(String serviceName, String version) {
            debug.warning("The schemaChanged ServiceListener method was invoked for service {}. This is unexpected.",
                    serviceName);
        }

        public void globalConfigChanged(String serviceName, String version, String groupName, String serviceComponent,
                int type) {
            debug.message("The globalConfigChanged ServiceListener method was invoked for service {}", serviceName);
            //if the global config changes, all organizationalConfig change listeners are invoked as well.
        }

        public void organizationConfigChanged(String serviceName, String version, String orgName, String groupName,
                String serviceComponent, int type) {
            switch(type) {
                case ServiceListener.ADDED:
                    debug.message("BaseURLProviderFactory: Removing stale service configuration state for realm {}", orgName);
                    providers.remove(DNMapper.orgNameToDN(orgName));
                    break;
                case ServiceListener.MODIFIED:
                    debug.message("BaseURLProviderFactory: Removing stale service configuration state for realm {}", orgName);
                    providers.remove(DNMapper.orgNameToDN(orgName));
                    break;
                case ServiceListener.REMOVED:
                    debug.message("BaseURLProviderFactory: Removing service configuration state for realm {}", orgName);
                    providers.remove(DNMapper.orgNameToDN(orgName));
                    break;
                default:
                    throw new IllegalArgumentException("Unknown change type: " + type);
            }
        }

    }

    private static enum ProviderType {
        FIXED_VALUE(FixedBaseURLProvider.class),
        FORWARDED_HEADER(ForwardedHeaderBaseURLProvider.class),
        X_FORWARDED_HEADERS(XForwardedHeadersBaseURLProvider.class),
        REQUEST_VALUES(RequestValuesBaseURLProvider.class),
        EXTENSION_CLASS(ExtensionBaseURLProvider.class);

        private final Class<? extends BaseURLProvider> providerClass;

        private ProviderType(Class<? extends BaseURLProvider> providerClass) {
            this.providerClass = providerClass;
        }
        public BaseURLProvider getProvider() {
            try {
                return providerClass.newInstance();
            } catch (Exception e) {
                throw new IllegalStateException("Could not initialise provider");
            }
        }
    }

}
