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
 * <h2>Kerberos configuration file</h2>
 *
 * Ensure that the host has a valid
 * <a href="http://web.mit.edu/kerberos/www/krb5-latest/doc/admin/conf_files/krb5_conf.html">Kerberos configuration file</a>,
 * with the Kerberos realm & KDC configured.
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
 * A JAAS configuration file with an entry named "{@value #JAAS_CONFIG_ITEM_NAME}" must be provided in order to
 * provide the configuration details of the GSS-API subject.
 *
 * Specify the location of the JAAS configuration file via the <code>java.security.auth.login.config</code>
 * system property or by adding an entry in the <code>java.security</code> properties file
 * (see <a href="https://docs.oracle.com/javase/8/docs/technotes/guides/security/PolicyFiles.html">here</a>
 * for more details).
 *
 * The following example JAAS configuration demonstrates Kerberos authentication via a TGT in the local ticket cache:
 *
 * <pre>{@code
 * {@value #JAAS_CONFIG_ITEM_NAME} {
 *    com.sun.security.auth.module.Krb5LoginModule required useTicketCache=true;
 * };
 * }</pre>
 *
 * The following example JAAS configuration demonstrates Kerberos authentication via a keytab:
 *
 * <pre>{@code
 * {@value #JAAS_CONFIG_ITEM_NAME} {
 *     com.sun.security.auth.module.Krb5LoginModule required
 *          storeKey=true
 *          principal="principal@MYREALM.COM"
 *          useKeyTab=true
 *          keyTab="/path/to/principal.keytab";
 * };
 * }</pre>
 *
 */
public class KerberosAuthProvider implements AuthProvider
{

    private static final Logger logger = LoggerFactory.getLogger(KerberosAuthProvider.class);

    private static final String JAAS_CONFIG_ITEM_NAME = "CassandraJavaClient";
    private static final String[] SASL_MECHANISMS = new String[]{"GSSAPI"};

    private static final String DEFAULT_SASL_PROTOCOL = "cassandra";
    private static final Map<String, String> DEFAULT_SASL_PROPERTIES =
            ImmutableMap.<String, String>builder()
                    .put(Sasl.SERVER_AUTH, "true")
                    .put(Sasl.QOP, "auth")
                    .build();

    private final String authorizationId;
    private final String saslProtocol;
    private final Map<String, ?> saslProperties;

    private KerberosAuthProvider(final String authorizationId, final String saslProtocol, final Map<String, ?> saslProperties)
    {
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

        private Builder() {}

        /**
         * Provide an authorization ID, representing a Cassandra user. The user will be assumed on behalf of the
         * client's principal.
         *
         * Note that the client principal must still exist as a Cassandra user, and the user
         * represented by the client's principal must have permission on the user represented by the authorization ID.
         *
         * For example, if the client application connects to a Cassandra cluster using the Kerberos principal
         * <code>admin@EXAMPLE.COM</code>, and an authorization ID of "demoapp", then the authenticator will assume
         * the Cassandra role of "demoapp", assuming that the Cassandra user "admin" exists and has permission on
         * role "demoapp".
         *
         * If not provided, the application will assume the cassandra role represented by the client's principal.
         *
         * See <a href="http://cassandra.apache.org/doc/latest/cql/security.html#grant-role">GRANT ROLE</a> for more
         * information.
         *
         * @param authorizationId Username of a Cassandra user to assume
         * @return the builder object
         */
        public Builder withAuthorizationId(String authorizationId)
        {
            this.authorizationId = authorizationId;
            return this;
        }

        /**
         * Provide a SASL protocol name. The protocol name must match the service principals used by the Cassandra nodes.
         *
         * For example, if the Cassandra nodes are configured to use service principals named
         * <code>cassandra/host1.cluster.example.com@EXAMPLE.COM</code>, then the SASL protocol name is "cassandra".
         *
         * If not provided, the default value of <code>{@value #DEFAULT_SASL_PROTOCOL}</code> is used.
         *
         * @param saslProtocol The name of the SASL protocol
         * @return the builder object
         */
        public Builder withSaslProtocol(String saslProtocol)
        {
            this.saslProtocol = saslProtocol;
            return this;
        }

        /**
         * Specify the SASL properties for authentication. Note that the QOP value must match that configured for the
         * Cassandra nodes.
         *
         * Note that if using Cassandra client TLS, a QOP value other than "auth" will provide redundant
         * encryption/integrity protection over that already provided by TLS.
         *
         * See <a href="https://docs.oracle.com/javase/8/docs/technotes/guides/security/sasl/sasl-refguide.html#CLIENT">here</a>
         * for further information.
         *
         * @param saslProperties SASL properties to apply to the connection.
         * @return the builder object
         */
        public Builder withSaslProperties(Map<String, ?> saslProperties)
        {
            this.saslProperties = saslProperties;
            return this;
        }

        public KerberosAuthProvider build()
        {
            return new KerberosAuthProvider(authorizationId, saslProtocol, saslProperties);
        }
    }

    @Override
    public Authenticator newAuthenticator(InetSocketAddress host, String authenticator) throws AuthenticationException
    {
        return new KerberosAuthenticator(authorizationId, saslProtocol, host, saslProperties);
    }

    public static class KerberosAuthenticator implements Authenticator
    {

        private final static Logger logger = LoggerFactory.getLogger(KerberosAuthenticator.class);

        private final Subject subject;
        private final SaslClient saslClient;

        private KerberosAuthenticator(String authorizationId, String saslProtocol, InetSocketAddress host, Map<String, ?> saslProperties)
        {
            this.subject = loginAsSubject();

            try {
                this.saslClient = Sasl.createSaslClient(
                        SASL_MECHANISMS,
                        authorizationId,
                        saslProtocol,
                        host.getAddress().getCanonicalHostName(),
                        saslProperties,
                        null);
            } catch (SaslException e) {
                throw new RuntimeException(e);
            }
        }

        /**
         * Login using a JAAS file entry named {@value #JAAS_CONFIG_ITEM_NAME}
         *
         * @return Authenticated Subject representing the principal retrieved from the login configuration
         */
        private static Subject loginAsSubject()
        {
            logger.debug("Logging in using login configuration entry named {}", JAAS_CONFIG_ITEM_NAME);

            try
            {
                // Don't need to supply a name, as it is ignored in the Configuration implementation
                final LoginContext loginContext = new LoginContext(JAAS_CONFIG_ITEM_NAME, cbh -> {
                    // Callback is called when login using the configuration fails
                    throw new RuntimeException(new LoginException("Failed to establish a login context using login " +
                            "configuration entry named " + JAAS_CONFIG_ITEM_NAME + ". Check your JAAS config file."));
                });
                loginContext.login();

                logger.debug("Login context established");
                return loginContext.getSubject();
            }
            catch (LoginException e)
            {
                throw new RuntimeException("Failed to establish a login context", e);
            }
        }

        @Override
        public byte[] initialResponse()
        {

            if (saslClient.hasInitialResponse())
            {
                try
                {
                    return Subject.doAs(subject, (PrivilegedExceptionAction<byte[]>) () ->
                            saslClient.evaluateChallenge(new byte[0]));
                } catch (PrivilegedActionException e)
                {
                    throw new RuntimeException(e.getException());
                }
            }

            return new byte[0];
        }

        @Override
        public byte[] evaluateChallenge(final byte[] challenge) {

            try
            {
                return Subject.doAs(subject, (PrivilegedExceptionAction<byte[]>) () ->
                        saslClient.evaluateChallenge(challenge));
            } catch (PrivilegedActionException e)
            {
                throw new RuntimeException(e.getException());
            }
        }

        @Override
        public void onAuthenticationSuccess(byte[] token)
        {
            if (saslClient.isComplete())
                logger.debug("Authenticated with QOP: {}", saslClient.getNegotiatedProperty(Sasl.QOP));
            else
                logger.error("Cassandra reports authentication success, however SASL authentication is not yet complete.");
        }
    }

}
