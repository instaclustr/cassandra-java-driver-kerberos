package com.instaclustr.cassandra.driver.auth;
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

import com.datastax.oss.driver.api.core.metadata.EndPoint;

import java.net.InetSocketAddress;

/**
 * Provide an option to override the server name that the SASL client uses when defining the server to authenticate to.
 * <br>
 * Specify a ServerNameResolver when the auth scheme requires something other than the resolved FQDN of the IP address
 * <p>
 * (see
 * <a href="https://docs.oracle.com/javase/8/docs/api/javax/security/sasl/Sasl.html#createSaslClient-java.lang.String:A-java.lang.String-java.lang.String-java.lang.String-java.util.Map-javax.security.auth.callback.CallbackHandler-">here</a>
 * for more details).
 */
public interface ServerNameResolver {

    /**
     * Define the mechanism for translating a Cassandra endpoint into a server name when creating the SASL Client.
     *
     * @param endpoint The Cassandra endpoint of the node to authenticate to.
     * @return The server name to be used in creating the SaslClient.
     */
    default String resolve(EndPoint endpoint) {
        return ((InetSocketAddress) endpoint.resolve()).getAddress().getCanonicalHostName();
    }

}