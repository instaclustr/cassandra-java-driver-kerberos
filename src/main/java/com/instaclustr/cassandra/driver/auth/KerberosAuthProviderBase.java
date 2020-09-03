package com.instaclustr.cassandra.driver.auth;

import static java.lang.String.format;

import javax.security.auth.Subject;
import javax.security.auth.login.LoginContext;
import javax.security.auth.login.LoginException;
import javax.security.sasl.Sasl;
import javax.security.sasl.SaslClient;
import javax.security.sasl.SaslException;
import java.nio.ByteBuffer;
import java.security.PrivilegedActionException;
import java.security.PrivilegedExceptionAction;
import java.util.Map;
import java.util.Objects;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.CompletionStage;

import com.datastax.oss.driver.api.core.auth.AuthProvider;
import com.datastax.oss.driver.api.core.auth.AuthenticationException;
import com.datastax.oss.driver.api.core.auth.Authenticator;
import com.datastax.oss.driver.api.core.config.DriverOption;
import com.datastax.oss.driver.api.core.metadata.EndPoint;
import com.datastax.oss.driver.shaded.guava.common.collect.ImmutableMap;
import edu.umd.cs.findbugs.annotations.NonNull;
import edu.umd.cs.findbugs.annotations.Nullable;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public abstract class KerberosAuthProviderBase implements AuthProvider
{

    private static final Logger LOG = LoggerFactory.getLogger(KerberosAuthProviderBase.class);

    private final String logPrefix;

    public KerberosAuthProviderBase(final String logPrefix)
    {
        this.logPrefix = logPrefix;
    }

    protected abstract KerberosAuthOptions getOptions(final EndPoint endPoint);

    @NonNull
    @Override
    public Authenticator newAuthenticator(@NonNull final EndPoint endPoint, @NonNull final String serverAuthenticator) throws AuthenticationException
    {
        return new KerberosAuthenticator(getOptions(endPoint), endPoint);
    }

    @Override
    public void onMissingChallenge(@NonNull final EndPoint endPoint) throws AuthenticationException
    {
        LOG.warn("[{}] {} did not send an authentication challenge; This is suspicious because the driver expects authentication", logPrefix, endPoint);
    }

    @Override
    public void close() throws Exception
    {
        // nothing to do
    }

    public static class KerberosAuthOptions
    {

        public static Builder builder()
        {
            return new Builder();
        }

        private final String authorizationId;
        private final ServerNameResolver serverNameResolver;
        private final String saslProtocol;
        private final Map<String, ?> saslProperties;

        private KerberosAuthOptions(final String authorizationId,
                                    final ServerNameResolver serverNameResolver,
                                    final String saslProtocol,
                                    final Map<String, ?> saslProperties)
        {
            this.authorizationId = authorizationId;
            this.serverNameResolver = serverNameResolver;
            this.saslProtocol = saslProtocol;
            this.saslProperties = saslProperties;
        }

        public String getAuthorizationId()
        {
            return authorizationId;
        }

        public ServerNameResolver getServerNameResolver()
        {
            return serverNameResolver;
        }

        public String getSaslProtocol()
        {
            return saslProtocol;
        }

        public Map<String, ?> getSaslProperties()
        {
            return saslProperties;
        }

        public static class Builder
        {

            private String authorizationId = null;
            private ServerNameResolver serverNameResolver = new ServerNameResolver()
            {
                // intentionally empty
            };
            private String saslProtocol = KerberosOption.DEFAULT_SASL_PROTOCOL;
            private Map<String, ?> saslProperties = KerberosOption.DEFAULT_SASL_PROPERTIES;

            private Builder()
            {

            }

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
            public Builder withAuthorizationId(final String authorizationId)
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
             * If not provided, the default value of <code>cassandra</code> is used.
             *
             * @param saslProtocol The name of the SASL protocol
             * @return the builder object
             */
            public Builder withSaslProtocol(final String saslProtocol)
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
            public Builder withSaslProperties(final Map<String, ?> saslProperties)
            {
                this.saslProperties = saslProperties;
                return this;
            }

            /**
             * Optional resolver for the serverName as part of the SASL Client API.  Defaults to the IP Addresses Canonical HostName.
             *
             * See <a href="https://docs.oracle.com/javase/8/docs/technotes/guides/security/sasl/sasl-refguide.html#CLIENT">here</a>
             * for further information.
             *
             * @param serverNameResolver The optional implementation of a resolver for the serverName
             * @return the builder object
             */
            public Builder withServerNameResolver(final ServerNameResolver serverNameResolver)
            {
                this.serverNameResolver = serverNameResolver;
                return this;
            }

            public KerberosAuthOptions build()
            {
                return new KerberosAuthOptions(authorizationId, serverNameResolver, saslProtocol, saslProperties);
            }
        }
    }

    private static class KerberosAuthenticator implements Authenticator
    {

        private final static Logger logger = LoggerFactory.getLogger(KerberosAuthenticator.class);

        private static final String JAAS_CONFIG_ITEM_NAME = "CassandraJavaClient";
        private static final String[] SASL_MECHANISMS = new String[]{"GSSAPI"};

        private final Subject subject;
        private final SaslClient saslClient;

        private KerberosAuthenticator(final KerberosAuthOptions options, final EndPoint endPoint)
        {
            Objects.requireNonNull(options.getSaslProperties(), "No SASL Properties supplied, unable to perform Kerberos authentication");

            this.subject = loginAsSubject();

            final String serverName = options.getServerNameResolver().resolve(endPoint);

            logger.debug("Creating SaslClient for {} on Server {} with {} mechanism. SASL Protocol: {} SASL Properties: {}",
                         options.getAuthorizationId(),
                         serverName,
                         SASL_MECHANISMS,
                         options.getSaslProtocol(),
                         options.getSaslProperties());

            try
            {
                this.saslClient = Sasl.createSaslClient(
                    SASL_MECHANISMS,
                    options.getAuthorizationId(),
                    options.getSaslProtocol(),
                    serverName,
                    options.getSaslProperties(),
                    null);
            } catch (SaslException e)
            {
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
                final LoginContext loginContext = new LoginContext(JAAS_CONFIG_ITEM_NAME, cbh ->
                {
                    // Callback is called when login using the configuration fails
                    throw new RuntimeException(new LoginException(format("Failed to establish a login context using login configuration entry named %s Check your JAAS config file.",
                                                                         JAAS_CONFIG_ITEM_NAME)));
                });

                loginContext.login();

                logger.debug("Login context established");
                return loginContext.getSubject();
            } catch (LoginException e)
            {
                throw new RuntimeException("Failed to establish a login context", e);
            }
        }

        @Override
        public CompletionStage<ByteBuffer> initialResponse()
        {

            if (saslClient.hasInitialResponse())
            {
                try
                {
                    byte[] response = Subject.doAs(subject, (PrivilegedExceptionAction<byte[]>) () ->
                        saslClient.evaluateChallenge(new byte[0]));
                    return CompletableFuture.completedFuture(ByteBuffer.wrap(response));
                } catch (PrivilegedActionException e)
                {
                    throw new RuntimeException(e.getException());
                }
            }

            return CompletableFuture.completedFuture(ByteBuffer.wrap(new byte[0]));
        }

        @Override
        public CompletionStage<ByteBuffer> evaluateChallenge(@Nullable ByteBuffer challenge)
        {
            try
            {
                byte[] bytes = new byte[challenge.capacity()];
                challenge.get(bytes, 0, bytes.length);

                byte[] evaluation = Subject.doAs(subject, (PrivilegedExceptionAction<byte[]>) () ->
                    saslClient.evaluateChallenge(bytes));
                return CompletableFuture.completedFuture(ByteBuffer.wrap(evaluation));
            } catch (PrivilegedActionException e)
            {
                throw new RuntimeException(e.getException());
            }
        }

        @Override
        public CompletionStage<Void> onAuthenticationSuccess(@Nullable ByteBuffer token)
        {
            if (saslClient.isComplete())
            {
                logger.debug("Authenticated with QOP: {}", saslClient.getNegotiatedProperty(Sasl.QOP));
            } else
            {
                logger.error("Cassandra reports authentication success, however SASL authentication is not yet complete.");
            }

            return CompletableFuture.completedFuture(null);
        }
    }

    public enum KerberosOption implements DriverOption
    {
        AUTH_PROVIDER_AUTHORIZATION_ID("advanced.auth-provider.authorization-id"),
        AUTH_PROVIDER_SASL_PROTOCOL("advanced.auth-provider.sasl-protocol"),
        AUTH_PROVIDER_SASL_PROPERTIES("advanced.auth-provider.sasl-properties"),
        AUTH_PROVIDER_SERVER_NAME_RESOLVER("advanced.auth-provider.server-name-resolver");

        public static final String DEFAULT_SASL_PROTOCOL = "cassandra";

        protected static final Map<String, String> DEFAULT_SASL_PROPERTIES =
            ImmutableMap.<String, String>builder()
                .put(Sasl.SERVER_AUTH, "true")
                .put(Sasl.QOP, "auth")
                .build();

        private final String path;

        KerberosOption(final String path)
        {
            this.path = path;
        }

        @NonNull
        @Override
        public String getPath()
        {
            return path;
        }
    }
}
