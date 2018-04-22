using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Net.Http;
using System.Security.Cryptography.X509Certificates;
using System.Threading.Tasks;
using System.Web;
using AuthTest2.Auth;
using DimensionData.Toolset.Configuration;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Authentication.WsFederation;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.IdentityModel.Protocols;
using Microsoft.IdentityModel.Protocols.WsFederation;
using Microsoft.IdentityModel.Tokens;
using Microsoft.Rest.Azure;

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
        public void ConfigureServices(IServiceCollection services)
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
        public void ConfigureServices2(IServiceCollection services)
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
            var stsReplyTo = Configuration["dimensionData:ui:sts:replyTo"];
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
