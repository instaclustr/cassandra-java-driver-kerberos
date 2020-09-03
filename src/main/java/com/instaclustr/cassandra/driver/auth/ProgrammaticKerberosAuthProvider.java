package com.instaclustr.cassandra.driver.auth;

import com.datastax.oss.driver.api.core.metadata.EndPoint;

/**
 * An AuthProvider implementation that provides authentication via GSS-API.
 * <br>
 * Specify this auth provider when creating a new Cluster object, as follows:
 *
 * <pre>{@code
 * CqlSession session = CqlSession.builder()
 *                      .addContactPoint(new InetSocketAddress(ipAddress, 9042))
 *                      .withAuthProvider(new ProgrammaticKerberosAuthProvider(KerberosAuthOptions.builder().build())).build();
 * }</pre>
 *
 * <h2>Kerberos configuration file</h2>
 *
 * Ensure that the host has a valid
 * <a href="http://web.mit.edu/kerberos/www/krb5-latest/doc/admin/conf_files/krb5_conf.html">Kerberos configuration file</a>,
 * with the Kerberos realm and KDC configured.
 *
 * <h2>SASL protocol name</h2>
 *
 * The SASL protocol name defaults to <code>{@link KerberosOption#DEFAULT_SASL_PROTOCOL}</code>. It can be configured using
 * the builder as follows:
 *
 * <pre>{@code
 *
 * CqlSession session = CqlSession.builder()
 *     .addContactPoint(new InetSocketAddress(ipAddress, 9042))
 *     .withAuthProvider(new ProgrammaticKerberosAuthProvider(KerberosAuthOptions.builder().withSaslProtocol("cassandra").build())).build();
 *
 * }</pre>
 *
 * The SASL protocol name <strong>must</strong> match the service principal configured for the
 * <a href="https://github.com/instaclustr/cassandra-kerberos">Kerberos authenticator plugin for Apache Cassandra</a>.
 * <br>
 * e.g. If your service principal is <code>cassandra/node1.cluster.example.com@EXAMPLE.COM</code>
 * then the SASL protocol name must be <code>cassandra</code>.
 *
 * <h2>Override SASL server name</h2>
 *
 * The SASL client will use the canonical host name from the contact point IP address. To override this behavior,
 * configured the builder with a custom ServerNameResolver as follows:
 *
 * <pre>{@code
 *
 * CqlSession session = CqlSession.builder()
 *     .addContactPoint(new InetSocketAddress(ipAddress, 9042))
 *     .withAuthProvider(new ProgrammaticKerberosAuthProvider(KerberosAuthOptions.builder().withServerNameResolver(new CustomServerNameResolver()).build())).build();
 * }</pre>
 *
 * <h2>JAAS configuration file</h2>
 * A JAAS configuration file with an entry named "CassandraJavaClient" must be provided in order to
 * provide the configuration details of the GSS-API subject.
 *
 * Specify the location of the JAAS configuration file via the <code>java.security.auth.login.config</code>
 * system property or by adding an entry in the <code>java.security</code> properties file
 * (see <a href="https://docs.oracle.com/javase/8/docs/technotes/guides/security/PolicyFiles.html">here</a>
 * for more details).
 *
 * The following example JAAS configuration demonstrates Kerberos authentication via a TGT in the local ticket cache:
 *
 * <pre><code>
 * CassandraJavaClient {
 *    com.sun.security.auth.module.Krb5LoginModule required useTicketCache=true;
 * };
 * </code></pre>
 *
 * The following example JAAS configuration demonstrates Kerberos authentication via a keytab:
 *
 * <pre><code>
 * CassandraJavaClient {
 *     com.sun.security.auth.module.Krb5LoginModule required
 *          storeKey=true
 *          principal="principal@MYREALM.COM"
 *          useKeyTab=true
 *          keyTab="/path/to/principal.keytab";
 * };
 * </code></pre>
 *
 */
public class ProgrammaticKerberosAuthProvider extends KerberosAuthProviderBase
{

    private final KerberosAuthOptions options;

    public ProgrammaticKerberosAuthProvider(final KerberosAuthOptions options)
    {
        super("Programmatic-Kerberos");
        this.options = options;
    }

    @Override
    protected KerberosAuthOptions getOptions(final EndPoint endPoint)
    {
        return options;
    }
}
