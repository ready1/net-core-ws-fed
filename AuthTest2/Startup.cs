using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Net.Http;
using System.Security.Claims;
using System.Security.Cryptography.X509Certificates;
using System.Threading.Tasks;
using System.Web;
using AuthTest2.Auth;
using AuthTest2.Models;
using DimensionData.ServiceLayer.Sdk.ApiClient;
using DimensionData.ServiceLayer.Sdk.Authentication;
using DimensionData.ServiceLayer.Sdk.Configuration;
using DimensionData.ServiceLayer.Sdk.ServiceDiscovery;
using DimensionData.ServiceLayer.Sdk.ServiceDiscovery.Client;
using DimensionData.Toolset.Security;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Authentication.WsFederation;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Protocols;
using Microsoft.IdentityModel.Protocols.WsFederation;
using Microsoft.IdentityModel.Tokens;
using Microsoft.Rest.Azure;
using SQLitePCL;

namespace AuthTest2
{
    public class Startup
    {
        public Startup(IConfiguration configuration)
        {
            Configuration = configuration;
        }

        public IConfiguration Configuration { get; }

        // This method gets called by the runtime. Use this method to add services to the container.
        public void ConfigureServices2(IServiceCollection services)
        {
            services.AddAuthentication(sharedOptions =>
            {
                sharedOptions.DefaultScheme = CookieAuthenticationDefaults.AuthenticationScheme;
                sharedOptions.DefaultSignInScheme = CookieAuthenticationDefaults.AuthenticationScheme;
                sharedOptions.DefaultChallengeScheme = WsFederationDefaults.AuthenticationScheme;
            })
            .AddWsFederation(options =>
            {
                options.Wtrealm = "https://cloud.dimensiondata.com/portal/v1/ci";
                options.MetadataAddress = "https://adfs-dev.gmgmt.dimensiondata.com/FederationMetadata/2007-06/federationmetadata.xml";

                options.Events = new WsFederationEvents
                {
                    OnRedirectToIdentityProvider = notifications =>
                    {
                        if (notifications.ProtocolMessage.IsSignInMessage)
                        {
                            // Read and set additional sign in parameters
                            string signInParameters = Configuration["dimensionData:ui:sts:signInParameters"];
                            if (!string.IsNullOrWhiteSpace(signInParameters))
                            {
                                signInParameters = HttpUtility.HtmlDecode(signInParameters);
                                Debug.Assert(signInParameters != null, "signInParameters != null");
                                string[] parameters = signInParameters.Split('&');
                                foreach (string param in parameters)
                                {
                                    string[] keyValue = param.Split('=');
                                    if (keyValue.Length > 0)
                                    {
                                        notifications.ProtocolMessage.Parameters.Add(keyValue[0], keyValue[1]);
                                    }
                                }
                            }
                        }
                        return Task.CompletedTask;
                    },
                    OnSecurityTokenValidated = context =>
                    {
                        var i = 0;
                        return Task.CompletedTask;
                    },
                    OnMessageReceived = context =>
                    {
                        var i = 0;
                        return Task.CompletedTask;
                    },
                    OnTicketReceived = context =>
                    {
                        var i = 0;
                        return Task.CompletedTask;
                    }
                };
            })
            .AddCookie();

            services.AddMvc();
        }

        // This method gets called by the runtime. Use this method to add services to the container.
        // TODO: Callbacks are not working
        public void ConfigureServices(IServiceCollection services)
        {
            var appKey = Configuration["dimensionData:ui:auth:appKey"];
            if (appKey == null)
            {
                throw new Exception("Missing AppKey configuration.");
            }

            var stsConfig = Configuration["dimensionData:ui:sts:certificateThumbprint"];
            if (stsConfig == null)
            {
                throw new Exception("Missing Ws-Federation authentication configuration.");
            }

            X509Certificate2 certificate;
            var stsCertificateThumbprint = Configuration["dimensionData:ui:sts:certificateThumbprint"];
            var stsCertificate = Configuration["dimensionData:ui:sts:certificate"];
            var stsRealm = Configuration["dimensionData:ui:sts:realm"];
            var stsReplyTo = Configuration["dimensionData:ui:sts:replyTo"] + "signin-wsfed";
            var stsIssuer = Configuration["dimensionData:ui:sts:issuer"];
            var stsSignInEndpoint = Configuration["dimensionData:ui:sts:signInEndpoint"];
            var stsSignInPath = Configuration["dimensionData:ui:sts:signInPath"];
            if (!string.IsNullOrEmpty(stsCertificateThumbprint))
            {
                certificate = Utils.GetCertificateByThumbprint(stsCertificateThumbprint);
                if (certificate == null)
                {
                    throw new Exception($"Certificate with thumbprint '{stsCertificateThumbprint}' not found in local store.");
                }
            }
            else if (!string.IsNullOrEmpty(stsCertificate))
            {
                certificate = Utils.GetCertificateByEncodedString(stsCertificate);
            }
            else
            {
                throw new Exception("No STS signing certificate defined.");
            }

//            var stsPublicKey = new X509AsymmetricSecurityKey(certificate);
            var stsPublicKey = new X509SecurityKey(certificate);

            // Check for signin endpoint over-ride
            Uri stsEndpoint;
            if (String.IsNullOrWhiteSpace(stsSignInEndpoint) || !Uri.TryCreate(stsSignInEndpoint, UriKind.Absolute, out stsEndpoint))
            {
                stsEndpoint = Utils.GetServiceEndpointFromDnsConvention(appKey: appKey);
            }

            services.AddAuthentication(sharedOptions =>
            {
                sharedOptions.DefaultScheme = CookieAuthenticationDefaults.AuthenticationScheme;
                sharedOptions.DefaultSignInScheme = CookieAuthenticationDefaults.AuthenticationScheme;
                sharedOptions.DefaultChallengeScheme = WsFederationDefaults.AuthenticationScheme;
            })
            .AddWsFederation(options =>
            {
                options.Wtrealm = stsRealm;
                options.Wreply = stsReplyTo;

                options.TokenValidationParameters = new TokenValidationParameters
                {
                    ValidateAudience = true,
                    ValidAudience = stsRealm,
                    ValidateIssuer = true,
                    ValidIssuer = stsIssuer,
                    ValidateIssuerSigningKey = true,
                    IssuerSigningKey = stsPublicKey
                };

                options.Configuration = new WsFederationConfiguration
                {
                    Issuer = stsIssuer,
                    TokenEndpoint = new Uri(stsEndpoint, stsSignInPath).ToString(),
                    SigningKeys =
                    {
                        stsPublicKey
                    }
                };

                options.Events = new WsFederationEvents
                {
                    OnRedirectToIdentityProvider = notifications =>
                    {
                        if (notifications.ProtocolMessage.IsSignInMessage)
                        {
                            // Read and set additional sign in parameters
                            string signInParameters = Configuration["dimensionData:ui:sts:signInParameters"];
                            if (!string.IsNullOrWhiteSpace(signInParameters))
                            {
                                signInParameters = HttpUtility.HtmlDecode(signInParameters);
                                Debug.Assert(signInParameters != null, "signInParameters != null");
                                string[] parameters = signInParameters.Split('&');
                                foreach (string param in parameters)
                                {
                                    string[] keyValue = param.Split('=');
                                    if (keyValue.Length > 0)
                                    {
                                        notifications.ProtocolMessage.Parameters.Add(keyValue[0], keyValue[1]);
                                    }
                                }
                            }
                        }
                        return Task.CompletedTask;
                    },
                    OnSecurityTokenValidated = async notifications =>
                    {
                        // Handle reverse proxy
                        //string[] protocols;
                        //if (notifications.Request.Headers.TryGetValue("X-Forwarded-Proto", out protocols))
                        //{
                        //    var isHttps = protocols.Contains("https", StringComparer.OrdinalIgnoreCase);
                        //    if (isHttps)
                        //    {
                        //        notifications.AuthenticationTicket.Properties.RedirectUri =
                        //            notifications.AuthenticationTicket.Properties.RedirectUri.Replace("http://", "https://");
                        //    }
                        //}

                        if (notifications.ProtocolMessage.IsSignInMessage)
                        {
                            var httpClient = CreateUpmClient(Configuration);

                            var formContent = OAuth2Request.GetOAuth2RequestContent(
                                "urn:ietf:params:oauth:grant-type:saml1-bearer",
                                notifications.ProtocolMessage.GetToken()
                            );

                            var response = await httpClient.PostAsync("oauth2/token", formContent);
                            if (!response.IsSuccessStatusCode)
                            {
                                var errorResponse = await response.Content.ReadAsStringAsync();

                                // Using Serilog directly (with logs location and settings preconfigured in Startup.Configuration)
                                // Have do to this due to the IOC contain with the ILogger service not yet available at this stage
                                //Serilog.Log.Logger.Warning(
                                //    "OAuth token exchange failed with status {0}. Response: {1}",
                                //    response.StatusCode,
                                //    errorResponse
                                //);
                                return;
                            }

                            var tokenResponse = await response.Content.ReadAsAsync<OAuth2ResponseModel>();
                            if (String.IsNullOrWhiteSpace(tokenResponse.AccessToken))
                            {
                                //Serilog.Log.Logger.Error("Failed to get a token from a OAuth token response.");
                                return;
                            }

                            string jwtClaimType = Configuration["dimensionData:ui:auth:jwtClaimType"];
                            var identity = new ClaimsIdentity(notifications.Principal.Identity, new[] { new Claim(jwtClaimType, tokenResponse.AccessToken) });
                            notifications.Principal = new ClaimsPrincipal(identity);
                        }
                    },
                    OnMessageReceived = context =>
                    {
                        var i = 0;
                        return Task.CompletedTask;
                    },
                    OnTicketReceived = context =>
                    {
                        var i = 0;
                        return Task.CompletedTask;
                    }
                };
            })
            .AddCookie();
            CreateUpmClient(Configuration);

            services.AddMvc();
        }


        private HttpClient CreateUpmClient(IConfiguration configuration)
        {
            var envOptions = new EnvironmentOptions();
            configuration.GetSection("dimensionData:environment").Bind(envOptions);
//            IServiceDiscoveryClient serviceDiscoveryClient = new ServiceDiscoveryClient(Options.Create(envOptions));
//
//            string upmKey = Configuration["dimensionData:ui:keys:upm"];
//            var baseAddress = serviceDiscoveryClient.FindGlobalApiService(upmKey).Result;
//            return new HttpClientBuilder()
//                .SetBaseAddress(baseAddress)
//                .SetRetryPolicy(3, TimeSpan.FromSeconds(1), 2)
//                .Build();

            return null;
        }


        // This method gets called by the runtime. Use this method to configure the HTTP request pipeline.
        public void Configure(IApplicationBuilder app, IHostingEnvironment env)
        {
            app.UseAuthentication();

            if (env.IsDevelopment())
            {
                app.UseBrowserLink();
                app.UseDeveloperExceptionPage();
            }
            else
            {
                app.UseExceptionHandler("/Home/Error");
            }

            app.UseStaticFiles();

            app.UseMvc(routes =>
            {
                routes.MapRoute(
                    name: "default",
                    template: "{controller=Home}/{action=Index}/{id?}");
            });
        }
    }
}
