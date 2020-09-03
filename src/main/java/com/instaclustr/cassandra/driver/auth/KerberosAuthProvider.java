/*
 * Licensed to Instaclustr Pty. Ltd. (Instaclustr) under one
 * or more contributor license agreements.  Instaclustr licenses this file
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

import static com.instaclustr.cassandra.driver.auth.KerberosAuthProviderBase.KerberosOption.AUTH_PROVIDER_AUTHORIZATION_ID;
import static com.instaclustr.cassandra.driver.auth.KerberosAuthProviderBase.KerberosOption.AUTH_PROVIDER_SASL_PROPERTIES;
import static com.instaclustr.cassandra.driver.auth.KerberosAuthProviderBase.KerberosOption.AUTH_PROVIDER_SASL_PROTOCOL;
import static com.instaclustr.cassandra.driver.auth.KerberosAuthProviderBase.KerberosOption.AUTH_PROVIDER_SERVER_NAME_RESOLVER;
import static java.lang.String.format;

import java.util.HashMap;
import java.util.Map;

import com.datastax.oss.driver.api.core.auth.AuthenticationException;
import com.datastax.oss.driver.api.core.config.DriverExecutionProfile;
import com.datastax.oss.driver.api.core.context.DriverContext;
import com.datastax.oss.driver.api.core.metadata.EndPoint;


/**
 * An AuthProvider implementation that provides authentication via GSS-API.
 * <br>
 * Specify this auth provider in file configuration as follows
 *
 * <pre>{@code
 * datastax-java-driver {
 *   advanced.auth-provider {
 *     class = com.instaclustr.cassandra.driver.auth.KerberosAuthProvider
 *     authorization-id = application will assume role "cassandra" when not specified
 *     sasl-protocol = "cassandra" when not specified
 *     sasl-properties = optional sasl properties map where keys and values are strings
 *     server-name-resolver = f.q.c.n of implementation of com.instaclustr.cassandra.driver.auth.ServerNameResolver, otherwise
 *   }
 * }
 * }</pre>
 *
 * Please follow the documentation in {@link ProgrammaticKerberosAuthProvider} to know more details about each configuration property.
 */
public class KerberosAuthProvider extends KerberosAuthProviderBase
{

    private final DriverExecutionProfile config;

    public KerberosAuthProvider(final DriverContext context)
    {
        super(context.getSessionName());
        this.config = context.getConfig().getDefaultProfile();
    }

    @Override
    protected KerberosAuthOptions getOptions(final EndPoint endPoint)
    {
        final KerberosAuthOptions.Builder optionsBuilder = KerberosAuthOptions.builder();

        if (config.isDefined(AUTH_PROVIDER_AUTHORIZATION_ID))
        {
            optionsBuilder.withAuthorizationId(config.getString(AUTH_PROVIDER_AUTHORIZATION_ID));
        }

        if (config.isDefined(AUTH_PROVIDER_SASL_PROPERTIES))
        {
            final Map<String, String> saslProperties = new HashMap<>();

            for (final Map.Entry<String, String> entry : config.getStringMap(AUTH_PROVIDER_SASL_PROPERTIES).entrySet())
            {
                saslProperties.put(entry.getKey(), entry.getValue());
            }

            optionsBuilder.withSaslProperties(saslProperties);
        }

        if (config.isDefined(AUTH_PROVIDER_SASL_PROTOCOL))
        {
            optionsBuilder.withSaslProtocol(config.getString(AUTH_PROVIDER_SASL_PROTOCOL));
        }

        if (config.isDefined(AUTH_PROVIDER_SERVER_NAME_RESOLVER))
        {
            final String serverNameResolverClassName = config.getString(AUTH_PROVIDER_SERVER_NAME_RESOLVER);

            try
            {
                final Class<?> serverNameResolverClass = Class.forName(serverNameResolverClassName);

                if (!serverNameResolverClass.isAssignableFrom(ServerNameResolver.class))
                {
                    throw new IllegalStateException(format("Class %s is not assignable from %s", serverNameResolverClassName, ServerNameResolver.class.getName()));
                }

                final ServerNameResolver serverNameResolver = (ServerNameResolver) serverNameResolverClass.newInstance();

                optionsBuilder.withServerNameResolver(serverNameResolver);
            } catch (final Exception ex)
            {
                throw new AuthenticationException(endPoint, "Unable to perform Kerberos authentication.", ex);
            }
        }

        return optionsBuilder.build();
    }
}