/*
 * Licensed to the Apache Software Foundation (ASF) under one
 * or more contributor license agreements.  See the NOTICE file
 * distributed with this work for additional information
 * regarding copyright ownership.  The ASF licenses this file
 * to you under the Apache License, Version 2.0 (the
 * "License"); you may not use this file except in compliance
 * with the License.  You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package com.instaclustr.cassandra.driver.auth;

import com.datastax.driver.core.AuthProvider;
import com.datastax.driver.core.Authenticator;
import com.datastax.driver.core.exceptions.AuthenticationException;
import com.google.common.collect.ImmutableMap;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.security.auth.Subject;
import javax.security.auth.login.LoginContext;
import javax.security.auth.login.LoginException;
import javax.security.sasl.Sasl;
import javax.security.sasl.SaslClient;
import javax.security.sasl.SaslException;
import java.net.InetSocketAddress;
import java.security.PrivilegedActionException;
import java.security.PrivilegedExceptionAction;
import java.util.Map;


/**
 * An AuthProvider implementation that provides authentication via GSS-API.
 * <br>
 * Specify this auth provider when creating a new Cluster object, as follows:
 *
 * <pre>{@code
 * Cluster cluster = Cluster.builder()
 *                      .addContactPoint(hostname)
 *                      .withAuthProvider(KerberosAuthProvider.builder().build()
 *                      .build();
 * }</pre>
 *
 * <h2>SASL protocol name</h2>
 *
 * The SASL protocol name defaults to <code>{@value #DEFAULT_SASL_PROTOCOL}</code>. It can be configured using
 * the builder as follows:
 *
 * <pre>{@code
 * Cluster cluster = Cluster.builder()
 *                      .addContactPoint(hostname)
 *                      .withAuthProvider(KerberosAuthProvider.builder()
 *                                          .withSaslProtocol("cassandra")
 *                                          .build())
 *                      .build();
 * }</pre>
 *
 * The SASL protocol name <strong>must</strong> match the service principal configured for the
 * <a href="https://github.com/instaclustr/cassandra-kerberos">Kerberos authenticator plugin for Apache Cassandra</a>.
 * <br>
 * e.g. If your service principal is <code>cassandra/node1.cluster.example.com@EXAMPLE.COM</code>
 * then the SASL protocol name must be <code>cassandra</code>.
 *
 * <h2>JAAS configuration file</h2>
 * A JAAS configuration file must be used in order to configure GSSAPI options.
 *
 * Specify the location of the JAAS configuration file via the <code>java.security.auth.login.config</code>
 * system property or by adding an entry in the <code>java.security</code> properties file
 * (see <a href="https://docs.oracle.com/javase/8/docs/technotes/guides/security/PolicyFiles.html">here</a>
 * for more details).
 *
 * The following example JAAS configuration demonstrates authentication via a keytab:
 * <pre>{@code
 * CassandraJavaClient {
 *     com.sun.security.auth.module.Krb5LoginModule required
 *          storeKey=true
 *          principal="principal@MYREALM.COM"
 *          useKeyTab=true
 *          keyTab="/path/to/principal.keytab"
 * };
 * }</pre>
 *
 */
public class KerberosAuthProvider implements AuthProvider {

    private static final String DEFAULT_SASL_PROTOCOL = "cassandra";
    private static final Map<String, String> DEFAULT_SASL_PROPERTIES =
            ImmutableMap.<String, String>builder()
                    .put(Sasl.SERVER_AUTH, "true")
                    .put(Sasl.QOP, "auth")
                    .build();

    private final String authorizationId;
    private final String saslProtocol;
    private final Map<String, ?> saslProperties;

    private KerberosAuthProvider(final String authorizationId, final String saslProtocol, final Map<String, ?> saslProperties) {
        this.authorizationId = authorizationId;
        this.saslProtocol = saslProtocol;
        this.saslProperties = ImmutableMap.copyOf(saslProperties);
    }

    public static Builder builder() {
        return new Builder();
    }

    public static class Builder {
        private String authorizationId = null;
        private String saslProtocol = DEFAULT_SASL_PROTOCOL;
        private Map<String, ?> saslProperties = DEFAULT_SASL_PROPERTIES;

        public Builder withAuthorizationId(String authorizationId) {
            this.authorizationId = authorizationId;
            return this;
        }

        public Builder withSaslProtocol(String saslProtocol) {
            this.saslProtocol = saslProtocol;
            return this;
        }

        public Builder withSaslProperties(Map<String, ?> saslProperties) {
            this.saslProperties = saslProperties;
            return this;
        }



        public KerberosAuthProvider build() {
            return new KerberosAuthProvider(authorizationId, saslProtocol, saslProperties);
        }
    }

    @Override
    public Authenticator newAuthenticator(InetSocketAddress host, String authenticator) throws AuthenticationException {
        return new KerberosAuthenticator(authorizationId, saslProtocol, host, saslProperties);
    }

    public static class KerberosAuthenticator implements Authenticator {

        private final Logger logger = LoggerFactory.getLogger(KerberosAuthenticator.class);

        private static final String JAAS_CONFIG_ITEM_NAME = "CassandraJavaClient";
        private static final String[] SASL_MECHANISMS = new String[]{"GSSAPI"};

        private final Subject subject;
        private final SaslClient saslClient;

        private KerberosAuthenticator(String authorizationId, String saslProtocol, InetSocketAddress host, Map<String, ?> saslProperties) {

            try {
                final LoginContext loginContext = new LoginContext(JAAS_CONFIG_ITEM_NAME);
                loginContext.login();

                this.subject = loginContext.getSubject();
                this.saslClient = Sasl.createSaslClient(
                        SASL_MECHANISMS,
                        authorizationId,
                        saslProtocol,
                        host.getAddress().getCanonicalHostName(),
                        saslProperties,
                        null);

            } catch (LoginException | SaslException e) {
                throw new RuntimeException(e);
            }
        }

        @Override
        public byte[] initialResponse() {

            if (saslClient.hasInitialResponse()) {
                try {
                    return Subject.doAs(subject, (PrivilegedExceptionAction<byte[]>) () ->
                            saslClient.evaluateChallenge(new byte[0]));
                } catch (PrivilegedActionException e) {
                    throw new RuntimeException(e.getException());
                }
            }

            return new byte[0];
        }

        @Override
        public byte[] evaluateChallenge(final byte[] challenge) {

            try {
                return Subject.doAs(subject, (PrivilegedExceptionAction<byte[]>) () ->
                        saslClient.evaluateChallenge(challenge));
            } catch (PrivilegedActionException e) {
                throw new RuntimeException(e.getException());
            }
        }

        @Override
        public void onAuthenticationSuccess(byte[] token) {
            // no-op
        }
    }

}
