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

package org.opensearch.security.ssl.transport;

import java.security.AccessController;
import java.security.PrivilegedAction;
import java.security.cert.CertificateParsingException;
import java.security.cert.X509Certificate;
import java.util.Collection;
import java.util.List;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import org.opensearch.SpecialPermission;

public class SPIFFEPrincipalExtractor implements PrincipalExtractor {

    protected final Logger log = LogManager.getLogger(this.getClass());

    @Override
    @SuppressWarnings("removal")
    public String extractPrincipal(final X509Certificate x509Certificate, final Type type) {
        if (x509Certificate == null) {
            return null;
        }

        final SecurityManager sm = System.getSecurityManager();

        if (sm != null) {
            sm.checkPermission(new SpecialPermission());
        }

        final Collection<List<?>> altNames = AccessController.doPrivileged(new PrivilegedAction<Collection<List<?>>>() {
            @Override
            public Collection<List<?>> run() {
                try {
                    return x509Certificate.getSubjectAlternativeNames();
                } catch (CertificateParsingException e) {
                    log.error("Unable to parse X509 altNames", e);
                    return null;
                }
            }
        });

        if (altNames == null) {
            return null;
        }

        for (List<?> sanItem : altNames) {
            if (sanItem == null || sanItem.size() < 2) {
                continue;
            }
            Integer altNameType = (Integer) sanItem.get(0);
            Object altNameValue = sanItem.get(1);
            if (altNameType != null && altNameType == 6 && altNameValue instanceof String) {
                String uriValue = (String) altNameValue;
                if (uriValue.startsWith("spiffe://")) {
                    if (log.isTraceEnabled()) {
                        log.trace("principal: CN={}", uriValue);
                    }
                    return String.format("CN=%s", uriValue);
                }
            }
        }
        return null;
    }
}
