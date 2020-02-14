# Cassandra Java Driver Kerberos Authenticator

A GSSAPI authentication provider for the [Cassandra Java driver](https://github.com/datastax/java-driver).

This driver plugin is intended to work with the 
[Cassandra kerberos authenticator](https://github.com/instaclustr/cassandra-kerberos) plugin for 
[Apache Cassandra](https://cassandra.apache.org/).

## Usage

The authenticator is distributed via Maven Central. To use, add the following dependency to your POM:

```
<dependency>
  <groupId>com.instaclustr</groupId>
  <artifactId>cassandra-driver-kerberos</artifactId>
  <version>1.0.0</version>
</dependency>
```

### Pre-requisite setup steps

- A Kerberos 5 KDC server is available
- An NTP client is installed & configured on the application host, each Cassandra node, and the KDC. Ideally the application host syncs 
  with the same time source as the KDC & Cassandra nodes in order to minimise potential time-sync issues.
- If using Oracle Java, ensure that the [Java Cryptographic Extensions Unlimited Strength Jurisdiction Policy Files](https://www.oracle.com/technetwork/java/javase/downloads/jce8-download-2133166.html)
  are installed (not necessary when using OpenJDK or other JRE implementations)
- Follow the instructions [here](https://github.com/instaclustr/cassandra-kerberos) to configure a Cassandra cluster for Kerberos authentication.

Configure the `/etc/krb5.conf` Kerberos config file (see [here](http://web.mit.edu/kerberos/www/krb5-latest/doc/admin/conf_files/krb5_conf.html) for further details).

An example `krb5.conf` for the `EXAMPLE.COM` realm:
    
```
[logging]
default = FILE:/var/log/krb5libs.log

[libdefaults]
 default_realm = EXAMPLE.COM
 dns_lookup_realm = false
 dns_lookup_kdc = false

[realms]
 EXAMPLE.COM = {
  kdc = kdc.example.com
  admin_server = kdc.example.com
}

[domain_realm]
 .example.com = EXAMPLE.COM
 example.com = EXAMPLE.COM
```
    
See [here](http://web.mit.edu/kerberos/www/krb5-latest/doc/admin/conf_files/krb5_conf.html) for further details.
    
    
### How to use the authenticator plugin

**Note:** *Please read the javadoc for full details on how to configure & use the plugin.*

The plugin works with the [Cassandra Java driver](https://github.com/datastax/java-driver):

```
CqlSession session = CqlSession.builder()
                      .addContactPoint(new InetSocketAddress(ipAddress, 9042))
                      .withAuthProvider(KerberosAuthProvider.builder().build()
                      .build();
```

A JAAS config file is also required. The following example retrieves a TGT from the local Kerberos ticket cache:

```
CassandraJavaClient {
   com.sun.security.auth.module.Krb5LoginModule required useTicketCache=true;
};
```
This particular example requires that the Kerberos client libraries & tools (`kinit` in particular) are installed.

The location of the JAAS config file must be provided via the `java.security.auth.login.config` system property.

For example:  `java -Djava.security.auth.login.config=/path/to/jaas.conf -jar MyApplication.jar`

## Build

If you would like to build the JAR package from source, checkout this project and run `mvn clean package`.

Please see https://www.instaclustr.com/support/documentation/announcements/instaclustr-open-source-project-status/ for Instaclustr support status of this project.
