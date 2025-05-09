/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 *
 * The OpenSearch Contributors require contributions made to
 * this file be licensed under the Apache-2.0 license or a
 * compatible open source license.
 *
 */
package org.opensearch.security.support;

import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.AccessController;
import java.security.PrivilegedAction;
import java.util.Comparator;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.stream.Collectors;

import com.google.common.collect.ImmutableSortedSet;
import com.google.common.hash.Hashing;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import org.opensearch.action.DocWriteRequest;
import org.opensearch.action.admin.indices.create.CreateIndexRequest;
import org.opensearch.action.bulk.BulkRequest;
import org.opensearch.action.get.MultiGetRequest;
import org.opensearch.action.get.MultiGetResponse;
import org.opensearch.action.index.IndexRequest;
import org.opensearch.action.support.WriteRequest;
import org.opensearch.common.settings.Settings;
import org.opensearch.common.util.concurrent.ThreadContext;
import org.opensearch.common.xcontent.XContentType;
import org.opensearch.core.action.ActionListener;
import org.opensearch.core.common.bytes.BytesReference;
import org.opensearch.core.xcontent.NamedXContentRegistry;
import org.opensearch.security.DefaultObjectMapper;
import org.opensearch.security.configuration.ConfigurationMap;
import org.opensearch.security.securityconf.impl.CType;
import org.opensearch.security.securityconf.impl.SecurityDynamicConfiguration;
import org.opensearch.security.state.SecurityConfig;
import org.opensearch.transport.client.Client;

import static org.opensearch.core.xcontent.DeprecationHandler.THROW_UNSUPPORTED_OPERATION;
import static org.opensearch.security.configuration.ConfigurationRepository.DEFAULT_CONFIG_VERSION;
import static org.opensearch.security.support.YamlConfigReader.emptyJsonConfigFor;
import static org.opensearch.security.support.YamlConfigReader.yamlContentFor;

public class SecurityIndexHandler {

    private final static int MINIMUM_HASH_BITS = 128;

    private static final Logger LOGGER = LogManager.getLogger(SecurityIndexHandler.class);

    private final Settings settings;

    private final Client client;

    private final String indexName;

    public SecurityIndexHandler(final String indexName, final Settings settings, final Client client) {
        this.indexName = indexName;
        this.settings = settings;
        this.client = client;
    }

    public final static Map<String, Object> INDEX_SETTINGS = Map.of("index.number_of_shards", 1, "index.auto_expand_replicas", "0-all");

    public void createIndex(ActionListener<Boolean> listener) {
        try (final ThreadContext.StoredContext threadContext = client.threadPool().getThreadContext().stashContext()) {
            client.admin()
                .indices()
                .create(
                    new CreateIndexRequest(indexName).settings(INDEX_SETTINGS).waitForActiveShards(1),
                    ActionListener.runBefore(ActionListener.wrap(r -> {
                        if (r.isAcknowledged()) {
                            listener.onResponse(true);
                        } else listener.onFailure(new SecurityException("Couldn't create security index " + indexName));
                    }, listener::onFailure), threadContext::restore)
                );
        }
    }

    @SuppressWarnings("removal")
    public void uploadDefaultConfiguration(final Path configDir, final ActionListener<Set<SecurityConfig>> listener) {
        try (final ThreadContext.StoredContext threadContext = client.threadPool().getThreadContext().stashContext()) {
            AccessController.doPrivileged((PrivilegedAction<Void>) () -> {
                try {
                    LOGGER.info("Uploading default security configuration from {}", configDir.toAbsolutePath());
                    final var bulkRequest = new BulkRequest().setRefreshPolicy(WriteRequest.RefreshPolicy.IMMEDIATE);
                    final var configuration = new ImmutableSortedSet.Builder<>(Comparator.comparing(SecurityConfig::type));
                    for (final var cType : CType.values()) {
                        final var fileExists = Files.exists(cType.configFile(configDir));
                        // Audit config is not packaged by default
                        if (cType == CType.AUDIT && !fileExists) continue;
                        final var yamlContent = yamlContentFor(cType, configDir);
                        final var hash = Hashing.goodFastHash(MINIMUM_HASH_BITS).hashBytes(yamlContent.toBytesRef().bytes);
                        configuration.add(new SecurityConfig(cType, hash.toString(), null));
                        bulkRequest.add(
                            new IndexRequest(indexName).id(cType.toLCString())
                                .opType(DocWriteRequest.OpType.INDEX)
                                .source(cType.toLCString(), yamlContent)
                        );
                    }
                    client.bulk(bulkRequest, ActionListener.runBefore(ActionListener.wrap(r -> {
                        if (r.hasFailures()) {
                            listener.onFailure(new SecurityException(r.buildFailureMessage()));
                            return;
                        }
                        listener.onResponse(configuration.build());
                    }, listener::onFailure), threadContext::restore));
                } catch (final IOException ioe) {
                    listener.onFailure(new SecurityException(ioe));
                }
                return null;
            });
        }
    }

    public void loadConfiguration(final Set<SecurityConfig> configuration, final ActionListener<ConfigurationMap> listener) {
        try (final ThreadContext.StoredContext threadContext = client.threadPool().getThreadContext().stashContext()) {
            client.threadPool().getThreadContext().putHeader(ConfigConstants.OPENDISTRO_SECURITY_CONF_REQUEST_HEADER, "true");
            final List<CType<?>> configurationTypes = configuration.stream()
                .map(SecurityConfig::type)
                .collect(Collectors.toUnmodifiableList());
            client.multiGet(newMultiGetRequest(configurationTypes), ActionListener.runBefore(ActionListener.wrap(r -> {
                final var cTypeConfigsBuilder = new ConfigurationMap.Builder();
                var hasFailures = false;
                for (final var item : r.getResponses()) {
                    if (item.isFailed()) {
                        listener.onFailure(new SecurityException(multiGetFailureMessage(item.getId(), item.getFailure())));
                        hasFailures = true;
                        break;
                    }
                    final var cType = CType.fromString(item.getId());
                    final var cTypeResponse = item.getResponse();
                    if (cTypeResponse.isExists() && !cTypeResponse.isSourceEmpty()) {
                        final var config = buildDynamicConfiguration(
                            cType,
                            cTypeResponse.getSourceAsBytesRef(),
                            cTypeResponse.getSeqNo(),
                            cTypeResponse.getPrimaryTerm()
                        );
                        if (config.getVersion() != DEFAULT_CONFIG_VERSION) {
                            listener.onFailure(
                                new SecurityException("Version " + config.getVersion() + " is not supported for " + cType.name())
                            );
                            hasFailures = true;
                            break;
                        }
                        cTypeConfigsBuilder.with(config);
                    } else {
                        if (!cType.emptyIfMissing()) {
                            listener.onFailure(new SecurityException("Missing required configuration for type: " + cType));
                            hasFailures = true;
                            break;
                        }
                        cTypeConfigsBuilder.with(
                            SecurityDynamicConfiguration.fromJson(
                                emptyJsonConfigFor(cType),
                                cType,
                                DEFAULT_CONFIG_VERSION,
                                cTypeResponse.getSeqNo(),
                                cTypeResponse.getPrimaryTerm()
                            )
                        );
                    }
                }
                if (!hasFailures) {
                    listener.onResponse(cTypeConfigsBuilder.build());
                }
            }, listener::onFailure), threadContext::restore));
        }
    }

    private MultiGetRequest newMultiGetRequest(final List<CType<?>> configurationTypes) {
        final var request = new MultiGetRequest().realtime(true).refresh(true);
        for (final var cType : configurationTypes) {
            request.add(indexName, cType.toLCString());
        }
        return request;
    }

    private SecurityDynamicConfiguration<?> buildDynamicConfiguration(
        final CType<?> cType,
        final BytesReference bytesRef,
        final long seqNo,
        final long primaryTerm
    ) {
        try {
            final var source = SecurityUtils.replaceEnvVars(configTypeSource(bytesRef.streamInput()), settings);
            final var jsonNode = DefaultObjectMapper.readTree(source);
            var version = 1;
            if (jsonNode.has("_meta")) {
                if (jsonNode.get("_meta").has("config_version")) {
                    version = jsonNode.get("_meta").get("config_version").asInt();
                }
            }
            return SecurityDynamicConfiguration.fromJson(source, cType, version, seqNo, primaryTerm);
        } catch (IOException e) {
            throw new SecurityException("Couldn't parse content for " + cType, e);
        }
    }

    private String configTypeSource(final InputStream inputStream) throws IOException {
        final var jsonContent = XContentType.JSON.xContent();
        try (final var parser = jsonContent.createParser(NamedXContentRegistry.EMPTY, THROW_UNSUPPORTED_OPERATION, inputStream)) {
            parser.nextToken();
            parser.nextToken();
            parser.nextToken();
            return new String(parser.binaryValue(), StandardCharsets.UTF_8);
        }
    }

    private String multiGetFailureMessage(final String cTypeId, final MultiGetResponse.Failure failure) {
        return String.format("Failure %s retrieving configuration for %s (index=%s)", failure, cTypeId, indexName);
    }

}
