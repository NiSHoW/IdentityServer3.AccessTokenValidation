﻿/*
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

using IdentityServer3.AccessTokenValidation;
using Microsoft.Owin.Extensions;
using Microsoft.Owin.Logging;
using Microsoft.Owin.Security.Jwt;
using Microsoft.Owin.Security.OAuth;
using System;
using System.Collections.Generic;
using Microsoft.IdentityModel.Tokens;
using System.Linq;
using System.Threading;
using IdentityModel;

namespace Owin
{
    /// <summary>
    /// AppBuilder extensions for identity server token validation
    /// </summary>
    public static class IdentityServerBearerTokenValidationAppBuilderExtensions
    {
        /// <summary>
        /// Add identity server token authentication to the pipeline.
        /// </summary>
        /// <param name="app">The application.</param>
        /// <param name="options">The options.</param>
        /// <returns></returns>
        public static IAppBuilder UseIdentityServerBearerTokenAuthentication(this IAppBuilder app, IdentityServerBearerTokenAuthenticationOptions options)
        {
            if (app == null) throw new ArgumentNullException("app");
            if (options == null) throw new ArgumentNullException("options");

            var loggerFactory = app.GetLoggerFactory();
            var middlewareOptions = new IdentityServerOAuthBearerAuthenticationOptions();

            switch (options.ValidationMode)
            {
                case ValidationMode.Local:
                    middlewareOptions.LocalValidationOptions = ConfigureLocalValidation(options, loggerFactory);
                    break;
                case ValidationMode.ValidationEndpoint:
                    middlewareOptions.EndpointValidationOptions = ConfigureEndpointValidation(options, loggerFactory);
                    break;
                case ValidationMode.Both:
                    middlewareOptions.LocalValidationOptions = ConfigureLocalValidation(options, loggerFactory);
                    middlewareOptions.EndpointValidationOptions = ConfigureEndpointValidation(options, loggerFactory);
                    break;
                default:
                    throw new Exception("ValidationMode has invalid value");
            }

            if (!options.DelayLoadMetadata)
            {
                // evaluate the lazy members so that they can do their job

                if (middlewareOptions.LocalValidationOptions != null)
                {
                    var ignore = middlewareOptions.LocalValidationOptions.Value;
                }

                if (middlewareOptions.EndpointValidationOptions != null)
                {
                    var ignore = middlewareOptions.EndpointValidationOptions.Value;
                }
            }

            if (options.TokenProvider != null)
            {
                middlewareOptions.TokenProvider = options.TokenProvider;
            }

            app.Use<IdentityServerBearerTokenValidationMiddleware>(app, middlewareOptions, loggerFactory);

            if (options.RequiredScopes.Any())
            {
                var scopeOptions = new ScopeRequirementOptions
                {
                    AuthenticationType = options.AuthenticationType,
                    RequiredScopes = options.RequiredScopes
                };

                app.Use<ScopeRequirementMiddleware>(scopeOptions);
            }

            if (options.PreserveAccessToken)
            {
                app.Use<PreserveAccessTokenMiddleware>();
            }

            app.UseStageMarker(PipelineStage.Authenticate);

            return app;
        }

        private static Lazy<OAuthBearerAuthenticationOptions> ConfigureEndpointValidation(IdentityServerBearerTokenAuthenticationOptions options, ILoggerFactory loggerFactory)
        {
            return new Lazy<OAuthBearerAuthenticationOptions>(() =>
            {
                if (options.EnableValidationResultCache)
                {
                    if (options.ValidationResultCache == null)
                    {
                        options.ValidationResultCache = new InMemoryValidationResultCache(options);
                    }
                }

                var bearerOptions = new OAuthBearerAuthenticationOptions
                {
                    AuthenticationMode = options.AuthenticationMode,
                    AuthenticationType = options.AuthenticationType,
                    Provider = new ContextTokenProvider(options.TokenProvider),
                };

                if (!string.IsNullOrEmpty(options.ApiName) || options.IntrospectionHttpHandler != null)
                {
                    bearerOptions.AccessTokenProvider = new IntrospectionEndpointTokenProvider(options, loggerFactory);
                }
                else
                {
                    bearerOptions.AccessTokenProvider = new ValidationEndpointTokenProvider(options, loggerFactory);
                }

                return bearerOptions;

            }, true);
        }

        internal static Lazy<OAuthBearerAuthenticationOptions> ConfigureLocalValidation(IdentityServerBearerTokenAuthenticationOptions options, ILoggerFactory loggerFactory)
        {
            return new Lazy<OAuthBearerAuthenticationOptions>(() =>
            {
                JwtFormat tokenFormat = null;

                // use static configuration
                if (!string.IsNullOrWhiteSpace(options.IssuerName) &&
                    options.SigningCertificate != null)
                {

                    string audience = null;
                    bool validateAudience = true;

                    // if API name is set, do a strict audience check for
                    //https://github.com/IdentityServer/IdentityServer4.AccessTokenValidation/blob/677bf6863a27c851270436faf9dfac437f46d90d/src/IdentityServerAuthenticationOptions.cs#L192
                    if (!string.IsNullOrWhiteSpace(options.ApiName) && !options.LegacyAudienceValidation)
                    {
                        audience = options.ApiName;
                    }
                    else if (options.LegacyAudienceValidation)
                    {
                        audience = options.IssuerName.EnsureTrailingSlash() + "resources";
                    }
                    else
                    {
                        // no audience validation, rely on scope checks only
                        validateAudience = false;
                    }

                    var valParams = new TokenValidationParameters
                    {
                        ValidIssuer = options.IssuerName,
                        ValidAudience = audience,
                        ValidateAudience = validateAudience,
                        IssuerSigningKey = new X509SecurityKey(options.SigningCertificate),
                        NameClaimType = options.NameClaimType,
                        RoleClaimType = options.RoleClaimType,
                    };

                    tokenFormat = new JwtFormat(valParams);
                }
                else
                {
                    // use discovery endpoint
                    if (string.IsNullOrWhiteSpace(options.Authority))
                    {
                        throw new Exception("Either set IssuerName and SigningCertificate - or Authority");
                    }

                    var discoveryEndpoint = options.Authority.EnsureTrailingSlash();
                    discoveryEndpoint += ".well-known/openid-configuration";

                    var issuerProvider = new DiscoveryDocumentIssuerSecurityTokenProvider(
                        discoveryEndpoint,
                        options,
                        loggerFactory);


                    string audience = issuerProvider.Audience;
                    bool validateAudience = true;

                    // if API name is set, do a strict audience check for
                    //https://github.com/IdentityServer/IdentityServer4.AccessTokenValidation/blob/677bf6863a27c851270436faf9dfac437f46d90d/src/IdentityServerAuthenticationOptions.cs#L192
                    if (string.IsNullOrWhiteSpace(audience) && !options.LegacyAudienceValidation)
                    {                    
                        // no audience validation, rely on scope checks only
                        validateAudience = false;
                    }


                    var valParams = new TokenValidationParameters
                    {
                        ValidAudience = audience,
                        ValidateAudience = validateAudience,
                        NameClaimType = options.NameClaimType,
                        RoleClaimType = options.RoleClaimType
                    };

                    if (options.IssuerSigningKeyResolver != null)
                    {
                        valParams.IssuerSigningKeyResolver = options.IssuerSigningKeyResolver;
                    }
                    else
                    {
                        valParams.IssuerSigningKeyResolver = IssuerSigningKeyResolver;
                    }

                    tokenFormat = new JwtFormat(valParams, issuerProvider);
                }


                var bearerOptions = new OAuthBearerAuthenticationOptions
                {
                    AccessTokenFormat = tokenFormat,
                    AuthenticationMode = options.AuthenticationMode,
                    AuthenticationType = options.AuthenticationType,
                    Provider = new ContextTokenProvider(options.TokenProvider)
                };

                return bearerOptions;

            }, LazyThreadSafetyMode.PublicationOnly);
        }

        private static IEnumerable<SecurityKey> IssuerSigningKeyResolver(string token, SecurityToken securityToken, string kid, TokenValidationParameters validationParameters)
        {
            // here kid (Certificate Thumbrint) is not the same as kid we get in DiscoveryDocumentIssuerSecurityTokenProvider (x5t, line 154) 
            // so as a temportal solution we will return all keys
            return validationParameters.IssuerSigningKeys;
        }
    }
}