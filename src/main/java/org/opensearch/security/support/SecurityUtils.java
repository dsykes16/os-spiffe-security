/*
 * Copyright 2015-2018 _floragunn_ GmbH
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
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

package org.opensearch.security.support;

import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.Locale;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import org.opensearch.common.settings.Settings;
import org.opensearch.security.tools.Hasher;

public final class SecurityUtils {

    protected final static Logger log = LogManager.getLogger(SecurityUtils.class);
    private static final String ENV_PATTERN_SUFFIX = "\\.([\\w=():\\-_]+?)(\\:\\-[\\w=():\\-_]*)?\\}";
    static final Pattern ENV_PATTERN = Pattern.compile("\\$\\{env" + ENV_PATTERN_SUFFIX);
    static final Pattern ENVBC_PATTERN = Pattern.compile("\\$\\{envbc" + ENV_PATTERN_SUFFIX);
    static final Pattern ENVBASE64_PATTERN = Pattern.compile("\\$\\{envbase64" + ENV_PATTERN_SUFFIX);
    public static Locale EN_Locale = forEN();

    private SecurityUtils() {}

    // https://github.com/tonywasher/bc-java/commit/ee160e16aa7fc71330907067c5470e9bf3e6c383
    // The Legion of the Bouncy Castle Inc
    private static Locale forEN() {
        if ("en".equalsIgnoreCase(Locale.getDefault().getLanguage())) {
            return Locale.getDefault();
        }

        Locale[] locales = Locale.getAvailableLocales();
        for (int i = 0; i != locales.length; i++) {
            if ("en".equalsIgnoreCase(locales[i].getLanguage())) {
                return locales[i];
            }
        }

        return Locale.getDefault();
    }

    public static String replaceEnvVars(String in, Settings settings) {
        if (in == null || in.isEmpty()) {
            return in;
        }

        if (settings == null || settings.getAsBoolean(ConfigConstants.SECURITY_DISABLE_ENVVAR_REPLACEMENT, false)) {
            return in;
        }

        return replaceEnvVarsBC(replaceEnvVarsNonBC(replaceEnvVarsBase64(in, settings), settings), settings);
    }

    private static String replaceEnvVarsNonBC(String in, Settings settings) {
        // ${env.MY_ENV_VAR}
        // ${env.MY_ENV_VAR:-default}
        Matcher matcher = ENV_PATTERN.matcher(in);
        StringBuffer sb = new StringBuffer();
        while (matcher.find()) {
            final String replacement = resolveEnvVar(matcher.group(1), matcher.group(2), false, settings);
            if (replacement != null) {
                matcher.appendReplacement(sb, Matcher.quoteReplacement(replacement));
            }
        }
        matcher.appendTail(sb);
        return sb.toString();
    }

    private static String replaceEnvVarsBC(String in, Settings settings) {
        // ${envbc.MY_ENV_VAR}
        // ${envbc.MY_ENV_VAR:-default}
        Matcher matcher = ENVBC_PATTERN.matcher(in);
        StringBuffer sb = new StringBuffer();
        while (matcher.find()) {
            final String replacement = resolveEnvVar(matcher.group(1), matcher.group(2), true, settings);
            if (replacement != null) {
                matcher.appendReplacement(sb, Matcher.quoteReplacement(replacement));
            }
        }
        matcher.appendTail(sb);
        return sb.toString();
    }

    private static String replaceEnvVarsBase64(String in, Settings settings) {
        // ${envbc.MY_ENV_VAR}
        // ${envbc.MY_ENV_VAR:-default}
        Matcher matcher = ENVBASE64_PATTERN.matcher(in);
        StringBuffer sb = new StringBuffer();
        while (matcher.find()) {
            final String replacement = resolveEnvVar(matcher.group(1), matcher.group(2), false, settings);
            if (replacement != null) {
                matcher.appendReplacement(
                    sb,
                    (Matcher.quoteReplacement(new String(Base64.getDecoder().decode(replacement), StandardCharsets.UTF_8)))
                );
            }
        }
        matcher.appendTail(sb);
        return sb.toString();
    }

    // ${env.MY_ENV_VAR}
    // ${env.MY_ENV_VAR:-default}
    private static String resolveEnvVar(String envVarName, String mode, boolean bc, Settings settings) {
        final String envVarValue = System.getenv(envVarName);
        if (envVarValue == null || envVarValue.isEmpty()) {
            if (mode != null && mode.startsWith(":-") && mode.length() > 2) {
                return bc ? Hasher.hash(mode.substring(2).toCharArray(), settings) : mode.substring(2);
            } else {
                return null;
            }
        } else {
            return bc ? Hasher.hash(envVarValue.toCharArray(), settings) : envVarValue;
        }
    }

    // Helper method to escape pipe characters
    public static String escapePipe(String input) {
        if (input == null) {
            return "";
        }
        return input.replace("|", "\\|");
    }
}
