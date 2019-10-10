/*
 * Copyright 2015 Dominick Baier, Brock Allen
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

using Microsoft.IdentityModel.Protocols;
using Microsoft.Owin.Logging;
using Microsoft.Owin.Security.Jwt;
using System;
using System.Collections.Generic;
using System.Net.Http;
using System.Security.Cryptography;
using System.Threading;
using Microsoft.IdentityModel.Protocols.OpenIdConnect;

namespace IdentityServer3.AccessTokenValidation
{
    internal class DiscoveryDocumentIssuerSecurityTokenProvider : IIssuerSecurityKeyProvider
    {
        private readonly ReaderWriterLockSlim _synclock = new ReaderWriterLockSlim();
        private readonly IConfigurationManager<OpenIdConnectConfiguration> _configurationManager;
        private readonly ILogger _logger;
        private readonly IdentityServerBearerTokenAuthenticationOptions _options;
        private string _issuer;
        private string _audience;
        private IEnumerable<Microsoft.IdentityModel.Tokens.SecurityKey> _keys;
        private DateTimeOffset _syncAfter = new DateTimeOffset(new DateTime(2001, 1, 1));
        private readonly TimeSpan _automaticRefreshInterval;

        public DiscoveryDocumentIssuerSecurityTokenProvider(string discoveryEndpoint, IdentityServerBearerTokenAuthenticationOptions options, ILoggerFactory loggerFactory)
        {
            _logger = loggerFactory.Create(this.GetType().FullName);
            _options = options;

            var handler = options.BackchannelHttpHandler ?? new WebRequestHandler();

            if (options.BackchannelCertificateValidator != null)
            {
                // Set the cert validate callback
                var webRequestHandler = handler as WebRequestHandler;
                if (webRequestHandler == null)
                {
                    throw new InvalidOperationException("The back channel handler must derive from WebRequestHandler in order to use a certificate validator");
                }
                webRequestHandler.ServerCertificateValidationCallback = options.BackchannelCertificateValidator.Validate;
            }

            var adapteeConfigurationManager = new ConfigurationManager<OpenIdConnectConfiguration>(discoveryEndpoint, new OpenIdConnectConfigurationRetriever(), new HttpDocumentRetriever(new HttpClient(handler)) { RequireHttps = options.RequireHttps })
            {
                AutomaticRefreshInterval = options.AutomaticRefreshInterval
            };

            _automaticRefreshInterval = adapteeConfigurationManager.AutomaticRefreshInterval;
            _configurationManager = new ConfigurationManagerAdapter(adapteeConfigurationManager);
            
            if (!options.DelayLoadMetadata)
            {
                RetrieveMetadata();
            }
        }

        /// <summary>
        /// Gets the issuer the credentials are for.
        /// </summary>
        /// <value>
        /// The issuer the credentials are for.
        /// </value>
        public string Issuer
        {
            get
            {
                RetrieveMetadata();
                _synclock.EnterReadLock();
                try
                {
                    return _issuer;
                }
                finally
                {
                    _synclock.ExitReadLock();
                }
            }
        }

        /// <value>
        /// The identity server default audience
        /// </value>
        public string Audience
        {
            get
            {
                RetrieveMetadata();
                _synclock.EnterReadLock();
                try
                {
                    return _audience;
                }
                finally
                {
                    _synclock.ExitReadLock();
                }
            }
        }

        /// <summary>
        /// Gets all known security tokens.
        /// </summary>
        /// <value>
        /// All known security tokens.
        /// </value>
        public IEnumerable<Microsoft.IdentityModel.Tokens.SecurityKey> SecurityKeys
        {
            get
            {
                RetrieveMetadata();
                _synclock.EnterReadLock();
                try
                {
                    return _keys;
                }
                finally
                {
                    _synclock.ExitReadLock();
                }
            }
        }

        private void RetrieveMetadata()
        {
            if (_syncAfter >= DateTimeOffset.UtcNow)
            {
                return;
            }

            _synclock.EnterWriteLock();
            try
            {
                var result = AsyncHelper.RunSync(() => _configurationManager.GetConfigurationAsync(CancellationToken.None));

                if (result.JsonWebKeySet == null)
                {
                    _logger.WriteError("Discovery document has no configured signing key. aborting.");
                    throw new InvalidOperationException("Discovery document has no configured signing key. aborting.");
                }

                var keys = new List<Microsoft.IdentityModel.Tokens.SecurityKey>();
                foreach (var key in result.JsonWebKeySet.Keys)
                {
                    var securityKey = new Microsoft.IdentityModel.Tokens.RsaSecurityKey(new RSAParameters
                    {
                        Exponent = Microsoft.IdentityModel.Tokens.Base64UrlEncoder.DecodeBytes(key.E),
                        Modulus = Microsoft.IdentityModel.Tokens.Base64UrlEncoder.DecodeBytes(key.N)
                    })
                    {
                        KeyId = key.Kid //key.KeyId is null (should be cert thumbprint)! Kid is x5t!
                    };
                    
                    keys.Add(securityKey);
                }

                _issuer = result.Issuer;
                _keys = keys;

                if (!string.IsNullOrWhiteSpace(_options.ApiName) && !_options.LegacyAudienceValidation)
                {
                    _audience = _options.ApiName;
                }
                else if (_options.LegacyAudienceValidation)
                {
                    _audience = _issuer.EnsureTrailingSlash() + "resources";
                } 
                else
                {
                    _audience = null;
                }

                _syncAfter = DateTimeOffset.UtcNow + _automaticRefreshInterval;
            }
            catch (Exception ex)
            {
                _logger.WriteError("Error contacting discovery endpoint: " + ex.ToString());
                throw;
            }
            finally
            {
                _synclock.ExitWriteLock();
            }
        }
    }
}