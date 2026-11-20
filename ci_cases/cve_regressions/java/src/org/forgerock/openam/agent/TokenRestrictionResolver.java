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
 * Copyright 2016 ForgeRock AS.
 * Portions Copyrighted 2012 Open Source Solution Technology Corporation
 * Portions 2006 Sun Microsystems Inc.
 * Portions copyright 2025 3A Systems LLC.
 */
package org.forgerock.openam.agent;

import java.io.UnsupportedEncodingException;
import java.net.MalformedURLException;
import java.net.URL;
import java.net.URLDecoder;
import java.net.UnknownHostException;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

import jakarta.inject.Inject;

import org.forgerock.openam.identity.idm.AMIdentityRepositoryFactory;
import org.forgerock.openam.identity.idm.IdentityUtils;
import org.forgerock.openam.utils.CollectionUtils;
import org.forgerock.openam.utils.StringUtils;
import org.forgerock.util.Reject;

import com.iplanet.dpro.session.TokenRestriction;
import com.iplanet.dpro.session.TokenRestrictionFactory;
import com.iplanet.sso.SSOException;
import com.iplanet.sso.SSOToken;
import com.sun.identity.idm.AMIdentity;
import com.sun.identity.idm.AMIdentityRepository;
import com.sun.identity.idm.IdRepoException;
import com.sun.identity.idm.IdSearchControl;
import com.sun.identity.idm.IdSearchOpModifier;
import com.sun.identity.idm.IdSearchResults;
import com.sun.identity.idm.IdType;
import com.sun.identity.sm.SMSException;

/**
 * Class to validate agents sending AuthN requests and the resource being accessed,
 * and return the token restriction.
 */
public class TokenRestrictionResolver {

    private static final String LDAP_ATTR_NAME = "sunIdentityServerDeviceKeyValue";
    private static final String LDAP_STATUS_ATTR_NAME = "sunIdentityServerDeviceStatus";
    private static final String PROVIDER_ID_ATTR_NAME = "agentRootURL";
    private static final String HOSTNAME_ATTR_NAME = "hostname";
    private static final String REALM_NAME_ATTR = "Realm";
    private static final String HTTPS = "https";
    private static final int HTTPS_DEFAULT_PORT = 443;
    private static final int HTTP_DEFAULT_PORT = 80;

    private final AMIdentityRepositoryFactory identityRepositoryFactory;
    private final TokenRestrictionFactory tokenRestrictionFactory;

    /**
     * Constructor of {@code LDAPAgentValidator} instances.
     *
     * @param identityRepositoryFactory Factory for creating {@code AMIdentityRepository} instances.
     * @param tokenRestrictionFactory   Factory for creating {@code TokenRestriction} instances.
     */
    @Inject
    public TokenRestrictionResolver(
            AMIdentityRepositoryFactory identityRepositoryFactory,
            TokenRestrictionFactory tokenRestrictionFactory) {
        this.identityRepositoryFactory = identityRepositoryFactory;
        this.tokenRestrictionFactory = tokenRestrictionFactory;
    }

    /**
     * Returns an appropriate token restriction for the given agent.
     *
     * @param agentId    The id of the agent.
     * @param realm      The realm.
     * @param adminToken The admin token.
     * @return The {@code TokenRestriction}.
     * @throws IdRepoException if the agent's attributes cannot be retrieved.
     * @throws SMSException    if a token restriction cannot be created.
     * @throws SSOException    if any of the inputs are invalid.
     */
    public TokenRestriction resolve(
            String agentId,
            String realm,
            SSOToken adminToken) throws IdRepoException, SMSException, SSOException {
        Reject.ifNull(agentId);
        Reject.ifNull(realm);
        Reject.ifNull(adminToken);

        Map<AMIdentity, Map<String, Set<String>>> agents = searchAgentById(agentId, realm, adminToken);
        AgentInfo agentInfo = getAgentInfo(agents);
        return createTokenRestriction(agentInfo);
    }

    /**
     * Returns an appropriate token restriction for the given agent.
     *
     * @param providerId           The request's provider id attribute.
     * @param gotoUrl              The goto url attribute.
     * @param adminToken           The admin token.
     * @param uniqueSSOTokenCookie {@code true} if unique SSO token cookie is enabled; {@code false} otherwise.
     * @return The {@code TokenRestriction}.
     * @throws IdRepoException if the agent's attributes cannot be retrieved.
     * @throws SMSException    if a token restriction cannot be created.
     * @throws SSOException    if any of the inputs are invalid.
     */
    public TokenRestriction resolve(
            String providerId,
            String gotoUrl,
            SSOToken adminToken,
            boolean uniqueSSOTokenCookie) throws IdRepoException, SMSException, SSOException {
        Reject.ifNull(providerId);
        Reject.ifNull(gotoUrl);
        Reject.ifNull(adminToken);

        if (!uniqueSSOTokenCookie) {
            return tokenRestrictionFactory.createNoOpTokenRestriction();
        }

        Map<AMIdentity, Map<String, Set<String>>> agents = searchAgentsByUri(providerId, adminToken);
        AgentInfo agentInfo = getAgentInfo(agents);
        if (isGotoUrlValid(gotoUrl, agentInfo.getRootUrls())) {
            return createTokenRestriction(agentInfo);
        } else {
            throw (new SSOException("Goto URL not valid for the agent Provider ID: " + gotoUrl));
        }
    }

    private Map<AMIdentity, Map<String, Set<String>>> searchAgentById(String agentId, String realm, SSOToken adminToken)
            throws SSOException {
        try {
            AMIdentityRepository identityRepository = identityRepositoryFactory.create(realm, adminToken);
            IdSearchResults searchResults = identityRepository.searchIdentities(
                    IdType.AGENT,
                    agentId,
                    getSearchOptions());
            Map<AMIdentity, Map<String, Set<String>>> agents = searchResults.getResultAttributes();
            if (agents.isEmpty()) {
                throw new SSOException("Invalid Agent: " + agentId + " not found.");
            }
            return agents;
        } catch (IdRepoException e) {
            throw new SSOException("Error searching Agent: " + agentId);
        }
    }

    private IdSearchControl getSearchOptions() {
        IdSearchControl idSearchControl = new IdSearchControl();
        idSearchControl.setRecursive(true);
        idSearchControl.setAllReturnAttributes(true);
        idSearchControl.setMaxResults(0);

        return idSearchControl;
    }

    private Map<AMIdentity, Map<String, Set<String>>> searchAgentsByUri(String uri, SSOToken adminToken)
            throws SSOException {
        String rootPrefix = null;
        try {
            URL url = new URL(URLDecoder.decode(uri, "UTF-8"));
            rootPrefix = url.getProtocol() + "://" + url.getHost() + ":" + getURLPort(url) + "/";
            AMIdentityRepository identityRepository =
                    identityRepositoryFactory.create(getRealmFromUrl(url), adminToken);
            IdSearchResults searchResults = identityRepository.searchIdentities(
                    IdType.AGENT,
                    "*",
                    getAgentIdSearchControl(rootPrefix));
            Map<AMIdentity, Map<String, Set<String>>> agents = searchResults.getResultAttributes();
            if (agents.isEmpty()) {
                throw new SSOException("Invalid Agent Root URL: " + rootPrefix + " not found.");
            }
            return agents;
        } catch (UnsupportedEncodingException | MalformedURLException e) {
            throw new SSOException("Invalid Agent Provider Id: " + uri);
        } catch (IdRepoException e) {
            throw new SSOException("Error searching Agents with Root URL: " + rootPrefix);
        }
    }

    private IdSearchControl getAgentIdSearchControl(String rootPrefix) {
        Set<String> attributeValues = new HashSet<>(2);
        attributeValues.add(PROVIDER_ID_ATTR_NAME + "=" + rootPrefix);
        Map<String, Set<String>> searchParameters = new HashMap<>();
        searchParameters.put(LDAP_ATTR_NAME, attributeValues);
        Set<String> returnAttributes = new HashSet<>(4);
        returnAttributes.add(LDAP_ATTR_NAME);
        returnAttributes.add(LDAP_STATUS_ATTR_NAME);

        IdSearchControl idSearchControl = new IdSearchControl();
        idSearchControl.setTimeOut(0);
        idSearchControl.setMaxResults(0);
        idSearchControl.setSearchModifiers(IdSearchOpModifier.AND, searchParameters);
        idSearchControl.setReturnAttributes(returnAttributes);

        return idSearchControl;
    }

    private String getRealmFromUrl(URL url) {
        String urlQuery = url.getQuery();
        if (urlQuery != null) {
            String[] params = urlQuery.split("&");
            for (String param : params) {
                String[] parts = param.split("=");
                String name = parts[0];
                if (name.equalsIgnoreCase(REALM_NAME_ATTR)) {
                    return StringUtils.isNotBlank(parts[1]) ? parts[1] : null;
                }
            }
        }
        return null;
    }

    private AgentInfo getAgentInfo(Map<AMIdentity, Map<String, Set<String>>> agents)
            throws IdRepoException, SSOException {
        List<AgentInfo> agentInfoList = new ArrayList<>();
        for (Object agent : agents.keySet()) {
            AMIdentity agentIdentity = (AMIdentity) agent;
            Map<String, Set<String>> agentAttributes = agentIdentity.getAttributes();
            if (agentAttributes != null && !agentAttributes.isEmpty()) {
                if (isAgentActive(agentAttributes)) {
                    Set<String> agentAttributeValues = agentAttributes.get(LDAP_ATTR_NAME);
                    if (agentAttributeValues != null && !agentAttributeValues.isEmpty()) {
                        agentInfoList.add(new AgentInfo(
                                IdentityUtils.getDN(agentIdentity),
                                getAgentHostNames(agentAttributeValues),
                                getAgentRootUrls(agentAttributeValues)));
                    }
                }
            }
        }
        return new AgentInfo(
                getAgentsDn(agentInfoList),
                getAgentsHostNames(agentInfoList),
                getAgentsRootUrls(agentInfoList));
    }

    private boolean isAgentActive(Map<String, Set<String>> attributes) {
        Set<String> statusAttributeValues = attributes.get(LDAP_STATUS_ATTR_NAME);
        if ((statusAttributeValues != null) && !statusAttributeValues.isEmpty()) {
            String status = statusAttributeValues.iterator().next();
            return status.equalsIgnoreCase("Active");
        }
        return false;
    }

    private List<URL> getAgentRootUrls(Set<String> agentAttributes) throws SSOException {
        List<URL> agentRootUrls = new ArrayList<>();
        for (Object attributeValue : agentAttributes) {
            String value = (String) attributeValue;
            if (value.startsWith(PROVIDER_ID_ATTR_NAME)) {
                String rootUrl = value.substring(PROVIDER_ID_ATTR_NAME.length() + 1);
                try {
                    agentRootUrls.add(new URL(rootUrl));
                } catch (MalformedURLException e) {
                    throw new SSOException("Invalid Agent Root URL: " + rootUrl);
                }
            }
        }
        return agentRootUrls;
    }

    private Set<String> getAgentHostNames(Set<String> agentAttributes) {
        Set<String> hostNames = new HashSet<>();
        for (Object attributeValue : agentAttributes) {
            String value = (String) attributeValue;
            if (value.startsWith(HOSTNAME_ATTR_NAME)) {
                hostNames.add(value.substring(HOSTNAME_ATTR_NAME.length() + 1));
            }
        }
        return hostNames;
    }

    private boolean isGotoUrlValid(String gotoUrl, List<URL> agentRootUrls) throws SSOException {
        try {
            URL url = new URL(gotoUrl);
            for (URL agentUrl : agentRootUrls) {
                if (agentUrl.getHost().equalsIgnoreCase(url.getHost()) &&
                        agentUrl.getProtocol().equalsIgnoreCase(url.getProtocol()) &&
                        (getURLPort(agentUrl) == getURLPort(url))) {
                    return true;
                }
            }
            return false;
        } catch (MalformedURLException e) {
            throw new SSOException("Invalid Goto URL: " + gotoUrl);
        }
    }

    private int getURLPort(URL url) {
        int port = url.getPort();
        if (port != -1) {
            return port;
        }
        return HTTPS.equalsIgnoreCase(url.getProtocol())
                ? HTTPS_DEFAULT_PORT
                : HTTP_DEFAULT_PORT;
    }

    private String getAgentsDn(List<AgentInfo> agentInfoList) {
        StringBuilder dn = null;
        for (AgentInfo info : agentInfoList) {
            if (StringUtils.isNotBlank(info.getDn())) {
                if (dn == null) {
                    dn = new StringBuilder();
                } else {
                    dn.append("|");
                }
                dn.append(info.getDn());
            }
        }
        return dn == null ? "" : dn.toString();
    }

    private Set<String> getAgentsHostNames(List<AgentInfo> agentInfoList) {
        Set<String> hostNames = new HashSet<>();
        for (AgentInfo info : agentInfoList) {
            if (CollectionUtils.isNotEmpty(info.getHostNames())) {
                hostNames.addAll(info.getHostNames());
            }
        }
        return hostNames;
    }

    private List<URL> getAgentsRootUrls(List<AgentInfo> agentInfoList) {
        List<URL> rootUrls = new ArrayList<>();
        for (AgentInfo info : agentInfoList) {
            if (CollectionUtils.isNotEmpty(info.getRootUrls())) {
                rootUrls.addAll(info.getRootUrls());
            }
        }
        return rootUrls;
    }

    private TokenRestriction createTokenRestriction(AgentInfo agentInfo) throws SMSException, SSOException {
        try {
            return tokenRestrictionFactory.createDNOrIPAddressListTokenRestriction(
                    agentInfo.getDn(),
                    agentInfo.getHostNames());
        } catch (UnknownHostException e) {
            throw new SSOException("Error creating token restriction");
        }
    }

    private static class AgentInfo {

        private final String dn;
        private final Set<String> hostNames;
        private final List<URL> rootUrls;

        AgentInfo(String dn, Set<String> hostNames, List<URL> rootUrls) {
            this.dn = dn;
            this.hostNames = hostNames;
            this.rootUrls = rootUrls;
            for (URL rootUrl : rootUrls) {
                String rootUrlHost = rootUrl.getHost().toLowerCase();
                this.hostNames.add(rootUrlHost);
            }
        }

        String getDn() {
            return dn;
        }

        Set<String> getHostNames() {
            return hostNames;
        }

        List<URL> getRootUrls() {
            return rootUrls;
        }
    }
}