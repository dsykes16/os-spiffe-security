/*
 * Copyright 2015-2017 floragunn GmbH
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 */
/*
 * SPDX-License-Identifier: Apache-2.0
 *
 * The OpenSearch Contributors require contributions made to
 * this file be licensed under the Apache-2.0 license or a
 * compatible open source license.
 *
 * Modifications Copyright OpenSearch Contributors. See
 * GitHub history for details.
 */

package org.opensearch.security.securityconf;

import java.io.IOException;
import java.nio.file.Path;
import java.util.Map;
import java.util.Map.Entry;
import java.util.concurrent.atomic.AtomicBoolean;

import com.google.common.collect.ImmutableMap;
import com.google.common.collect.ImmutableSet;
import com.fasterxml.jackson.databind.JsonNode;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import org.opensearch.common.settings.Settings;
import org.opensearch.common.util.concurrent.ThreadContext;
import org.opensearch.security.DefaultObjectMapper;
import org.opensearch.security.auditlog.config.AuditConfig;
import org.opensearch.security.auth.internal.InternalAuthenticationBackend;
import org.opensearch.security.configuration.ClusterInfoHolder;
import org.opensearch.security.configuration.ConfigurationChangeListener;
import org.opensearch.security.configuration.ConfigurationMap;
import org.opensearch.security.configuration.ConfigurationRepository;
import org.opensearch.security.configuration.SecurityConfigVersionHandler;
import org.opensearch.security.configuration.StaticResourceException;
import org.opensearch.security.hasher.PasswordHasher;
import org.opensearch.security.securityconf.impl.AllowlistingSettings;
import org.opensearch.security.securityconf.impl.CType;
import org.opensearch.security.securityconf.impl.NodesDn;
import org.opensearch.security.securityconf.impl.SecurityDynamicConfiguration;
import org.opensearch.security.securityconf.impl.v7.ActionGroupsV7;
import org.opensearch.security.securityconf.impl.v7.ConfigV7;
import org.opensearch.security.securityconf.impl.v7.InternalUserV7;
import org.opensearch.security.securityconf.impl.v7.RoleMappingsV7;
import org.opensearch.security.securityconf.impl.v7.RoleV7;
import org.opensearch.security.securityconf.impl.v7.TenantV7;
import org.opensearch.security.support.ConfigConstants;
import org.opensearch.security.support.WildcardMatcher;
import org.opensearch.threadpool.ThreadPool;
import org.opensearch.transport.client.Client;

import org.greenrobot.eventbus.EventBus;
import org.greenrobot.eventbus.EventBusBuilder;
import org.greenrobot.eventbus.Logger.JavaLogger;

public class DynamicConfigFactory implements Initializable, ConfigurationChangeListener {

    public static final EventBusBuilder EVENT_BUS_BUILDER = EventBus.builder();
    private static SecurityDynamicConfiguration<RoleV7> staticRoles = SecurityDynamicConfiguration.empty(CType.ROLES);
    private static SecurityDynamicConfiguration<ActionGroupsV7> staticActionGroups = SecurityDynamicConfiguration.empty(CType.ACTIONGROUPS);
    private static SecurityDynamicConfiguration<TenantV7> staticTenants = SecurityDynamicConfiguration.empty(CType.TENANTS);
    private static final AllowlistingSettings defaultAllowlistingSettings = new AllowlistingSettings();
    private static final AuditConfig defaultAuditConfig = AuditConfig.from(Settings.EMPTY);

    static void resetStatics() {
        staticRoles = SecurityDynamicConfiguration.empty(CType.ROLES);
        staticActionGroups = SecurityDynamicConfiguration.empty(CType.ACTIONGROUPS);
        staticTenants = SecurityDynamicConfiguration.empty(CType.TENANTS);
    }

    private void loadStaticConfig() throws IOException {
        JsonNode staticRolesJsonNode = DefaultObjectMapper.YAML_MAPPER.readTree(
            DynamicConfigFactory.class.getResourceAsStream("/static_config/static_roles.yml")
        );
        staticRoles = SecurityDynamicConfiguration.fromNode(staticRolesJsonNode, CType.ROLES, 2, 0, 0);

        JsonNode staticActionGroupsJsonNode = DefaultObjectMapper.YAML_MAPPER.readTree(
            DynamicConfigFactory.class.getResourceAsStream("/static_config/static_action_groups.yml")
        );
        staticActionGroups = SecurityDynamicConfiguration.fromNode(staticActionGroupsJsonNode, CType.ACTIONGROUPS, 2, 0, 0);

        JsonNode staticTenantsJsonNode = DefaultObjectMapper.YAML_MAPPER.readTree(
            DynamicConfigFactory.class.getResourceAsStream("/static_config/static_tenants.yml")
        );
        staticTenants = SecurityDynamicConfiguration.fromNode(staticTenantsJsonNode, CType.TENANTS, 2, 0, 0);
    }

    public final static <T> SecurityDynamicConfiguration<T> addStatics(SecurityDynamicConfiguration<T> original) {
        if (original.getCType() == CType.ACTIONGROUPS && !staticActionGroups.getCEntries().isEmpty()) {
            original.add(staticActionGroups.deepClone());
        }

        if (original.getCType() == CType.ROLES && !staticRoles.getCEntries().isEmpty()) {
            original.add(staticRoles.deepClone());
        }

        if (original.getCType() == CType.TENANTS && !staticTenants.getCEntries().isEmpty()) {
            original.add(staticTenants.deepClone());
        }

        return original;
    }

    protected final Logger log = LogManager.getLogger(this.getClass());
    private final ConfigurationRepository cr;
    private final AtomicBoolean initialized = new AtomicBoolean();
    private final EventBus eventBus = EVENT_BUS_BUILDER.logger(new JavaLogger(DynamicConfigFactory.class.getCanonicalName())).build();
    private final Settings opensearchSettings;
    private final Path configPath;
    private final InternalAuthenticationBackend iab;
    private final ClusterInfoHolder cih;
    private final ThreadPool threadPool;
    private final Client client;

    SecurityDynamicConfiguration<?> config;

    public DynamicConfigFactory(
        ConfigurationRepository cr,
        final Settings opensearchSettings,
        final Path configPath,
        Client client,
        ThreadPool threadPool,
        ClusterInfoHolder cih,
        PasswordHasher passwordHasher
    ) {
        super();
        this.cr = cr;
        this.opensearchSettings = opensearchSettings;
        this.configPath = configPath;
        this.cih = cih;
        this.iab = new InternalAuthenticationBackend(passwordHasher);
        this.threadPool = threadPool;
        this.client = client;

        if (opensearchSettings.getAsBoolean(ConfigConstants.SECURITY_UNSUPPORTED_LOAD_STATIC_RESOURCES, true)) {
            try {
                loadStaticConfig();
            } catch (IOException e) {
                throw new StaticResourceException("Unable to load static resources due to " + e, e);
            }
        } else {
            log.info("Static resources will not be loaded.");
        }

        ThreadContext threadContext = threadPool.getThreadContext();
        SecurityConfigVersionHandler versionHandler = new SecurityConfigVersionHandler(
            cr,
            opensearchSettings,
            threadContext,
            threadPool,
            client,
            this.cih
        );
        cr.subscribeOnChange(versionHandler);

        registerDCFListener(this.iab);
        this.cr.subscribeOnChange(this);
    }

    @Override
    @SuppressWarnings("unchecked")
    public void onChange(ConfigurationMap typeToConfig) {

        SecurityDynamicConfiguration<ActionGroupsV7> actionGroups = cr.getConfiguration(CType.ACTIONGROUPS);
        config = cr.getConfiguration(CType.CONFIG);
        SecurityDynamicConfiguration<InternalUserV7> internalusers = cr.getConfiguration(CType.INTERNALUSERS);
        SecurityDynamicConfiguration<RoleV7> roles = cr.getConfiguration(CType.ROLES);
        SecurityDynamicConfiguration<RoleMappingsV7> rolesmapping = cr.getConfiguration(CType.ROLESMAPPING);
        SecurityDynamicConfiguration<TenantV7> tenants = cr.getConfiguration(CType.TENANTS);
        SecurityDynamicConfiguration<NodesDn> nodesDn = cr.getConfiguration(CType.NODESDN);
        SecurityDynamicConfiguration<AllowlistingSettings> allowlistingSetting = cr.getConfiguration(CType.ALLOWLIST);

        if (log.isDebugEnabled()) {
            String logmsg = "current config (because of "
                + typeToConfig.keySet()
                + ")\n"
                + " actionGroups: "
                + actionGroups.getImplementingClass()
                + " with "
                + actionGroups.getCEntries().size()
                + " entries\n"
                + " config: "
                + config.getImplementingClass()
                + " with "
                + config.getCEntries().size()
                + " entries\n"
                + " internalusers: "
                + internalusers.getImplementingClass()
                + " with "
                + internalusers.getCEntries().size()
                + " entries\n"
                + " roles: "
                + roles.getImplementingClass()
                + " with "
                + roles.getCEntries().size()
                + " entries\n"
                + " rolesmapping: "
                + rolesmapping.getImplementingClass()
                + " with "
                + rolesmapping.getCEntries().size()
                + " entries\n"
                + " tenants: "
                + tenants.getImplementingClass()
                + " with "
                + tenants.getCEntries().size()
                + " entries\n"
                + " nodesdn: "
                + nodesDn.getImplementingClass()
                + " with "
                + nodesDn.getCEntries().size()
                + " entries\n"
                + " allowlist "
                + allowlistingSetting.getImplementingClass()
                + " with "
                + allowlistingSetting.getCEntries().size()
                + " entries\n";
            log.debug(logmsg);
        }

        final DynamicConfigModel dcm;
        final InternalUsersModel ium;
        final ConfigModel cm;
        final NodesDnModel nm = new NodesDnModelImpl(nodesDn);
        final AllowlistingSettings allowlist = cr.getConfiguration(CType.ALLOWLIST).getCEntry("config");
        final AuditConfig audit = cr.getConfiguration(CType.AUDIT).getCEntry("config");

        if (roles.containsAny(staticRoles)) {
            throw new StaticResourceException("Cannot override static roles");
        }
        if (!roles.add(staticRoles) && !staticRoles.getCEntries().isEmpty()) {
            throw new StaticResourceException("Unable to load static roles");
        }

        log.debug("Static roles loaded ({})", staticRoles.getCEntries().size());

        if (actionGroups.containsAny(staticActionGroups)) {
            throw new StaticResourceException("Cannot override static action groups");
        }
        if (!actionGroups.add(staticActionGroups) && !staticActionGroups.getCEntries().isEmpty()) {
            throw new StaticResourceException("Unable to load static action groups");
        }

        log.debug("Static action groups loaded ({})", staticActionGroups.getCEntries().size());

        if (tenants.containsAny(staticTenants)) {
            throw new StaticResourceException("Cannot override static tenants");
        }
        if (!tenants.add(staticTenants) && !staticTenants.getCEntries().isEmpty()) {
            throw new StaticResourceException("Unable to load static tenants");
        }

        log.debug("Static tenants loaded ({})", staticTenants.getCEntries().size());

        log.debug(
            "Static configuration loaded (total roles: {}/total action groups: {}/total tenants: {})",
            roles.getCEntries().size(),
            actionGroups.getCEntries().size(),
            tenants.getCEntries().size()
        );

        // rebuild v7 Models
        dcm = new DynamicConfigModelV7(getConfigV7(config), opensearchSettings, configPath, iab, this.cih);
        ium = new InternalUsersModelV7(internalusers, roles, rolesmapping);
        cm = new ConfigModelV7(roles, rolesmapping, dcm, opensearchSettings);

        // notify subscribers
        eventBus.post(cm);
        eventBus.post(dcm);
        eventBus.post(ium);
        eventBus.post(nm);
        eventBus.post(allowlist == null ? defaultAllowlistingSettings : allowlist);
        if (cr.isAuditHotReloadingEnabled()) {
            eventBus.post(audit == null ? defaultAuditConfig : audit);
        }

        log.debug("Dispatched config update notification to different subscribers");

        initialized.set(true);
    }

    private static ConfigV7 getConfigV7(SecurityDynamicConfiguration<?> sdc) {
        @SuppressWarnings("unchecked")
        SecurityDynamicConfiguration<ConfigV7> c = (SecurityDynamicConfiguration<ConfigV7>) sdc;
        return c.getCEntry("config");
    }

    @Override
    public boolean isInitialized() {
        return initialized.get();
    }

    public void registerDCFListener(Object listener) {
        eventBus.register(listener);
    }

    public void unregisterDCFListener(Object listener) {
        eventBus.unregister(listener);
    }

    private static class InternalUsersModelV7 extends InternalUsersModel {

        private final SecurityDynamicConfiguration<InternalUserV7> internalUserV7SecurityDynamicConfiguration;

        private final SecurityDynamicConfiguration<RoleV7> rolesV7SecurityDynamicConfiguration;

        private final SecurityDynamicConfiguration<RoleMappingsV7> rolesMappingsV7SecurityDynamicConfiguration;

        public InternalUsersModelV7(
            SecurityDynamicConfiguration<InternalUserV7> internalUserV7SecurityDynamicConfiguration,
            SecurityDynamicConfiguration<RoleV7> rolesV7SecurityDynamicConfiguration,
            SecurityDynamicConfiguration<RoleMappingsV7> rolesMappingsV7SecurityDynamicConfiguration
        ) {
            super();
            this.internalUserV7SecurityDynamicConfiguration = internalUserV7SecurityDynamicConfiguration;
            this.rolesV7SecurityDynamicConfiguration = rolesV7SecurityDynamicConfiguration;
            this.rolesMappingsV7SecurityDynamicConfiguration = rolesMappingsV7SecurityDynamicConfiguration;
        }

        @Override
        public boolean exists(String user) {
            return internalUserV7SecurityDynamicConfiguration.exists(user);
        }

        @Override
        public ImmutableSet<String> getBackendRoles(String user) {
            InternalUserV7 tmp = internalUserV7SecurityDynamicConfiguration.getCEntry(user);
            return tmp == null ? ImmutableSet.of() : ImmutableSet.copyOf(tmp.getBackend_roles());
        }

        @Override
        public ImmutableMap<String, String> getAttributes(String user) {
            InternalUserV7 tmp = internalUserV7SecurityDynamicConfiguration.getCEntry(user);
            return tmp == null ? ImmutableMap.of() : ImmutableMap.copyOf(tmp.getAttributes());
        }

        @Override
        public String getDescription(String user) {
            InternalUserV7 tmp = internalUserV7SecurityDynamicConfiguration.getCEntry(user);
            return tmp == null ? null : tmp.getDescription();
        }

        @Override
        public String getHash(String user) {
            InternalUserV7 tmp = internalUserV7SecurityDynamicConfiguration.getCEntry(user);
            return tmp == null ? null : tmp.getHash();
        }

        public ImmutableSet<String> getSecurityRoles(String user) {
            InternalUserV7 tmp = internalUserV7SecurityDynamicConfiguration.getCEntry(user);

            // Security roles should only contain roles that exist in the roles dynamic config.
            // We should filter out any roles that have hidden rolesmapping.
            return tmp == null
                ? ImmutableSet.of()
                : tmp.getOpendistro_security_roles()
                    .stream()
                    .filter(role -> !isRolesMappingHidden(role) && rolesV7SecurityDynamicConfiguration.exists(role))
                    .collect(ImmutableSet.toImmutableSet());
        }

        // Remove any hidden rolesmapping from the security roles
        private boolean isRolesMappingHidden(String rolename) {
            final RoleMappingsV7 roleMapping = rolesMappingsV7SecurityDynamicConfiguration.getCEntry(rolename);
            return roleMapping != null && roleMapping.isHidden();
        }
    }

    private static class NodesDnModelImpl extends NodesDnModel {

        SecurityDynamicConfiguration<NodesDn> configuration;

        @SuppressWarnings("unchecked")
        public NodesDnModelImpl(SecurityDynamicConfiguration<?> configuration) {
            super();
            this.configuration = null == configuration.getCType()
                ? SecurityDynamicConfiguration.empty(CType.NODESDN)
                : (SecurityDynamicConfiguration<NodesDn>) configuration;
        }

        @Override
        public Map<String, WildcardMatcher> getNodesDn() {
            return this.configuration.getCEntries()
                .entrySet()
                .stream()
                .collect(
                    ImmutableMap.toImmutableMap(Entry::getKey, entry -> WildcardMatcher.from(entry.getValue().getNodesDn()).ignoreCase())
                );
        }
    }
}
