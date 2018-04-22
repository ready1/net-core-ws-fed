using System;
using System.Security.Cryptography.X509Certificates;
using DimensionData.Toolset.ServiceDiscovery;
using DimensionData.Toolset.Validation;

namespace AuthTest2.Auth
{
    internal static class Utils
    {
        /// <summary>
        ///     Get endpoint address from Service Discovery.
        /// </summary>
        /// <param name="serviceName">Name of service to discover.</param>
        /// <param name="appKey">The application key of the endpoint.</param>
        /// <param name="locationKey">The location key of the endpoint.</param>
        /// <returns>The endpoint of the discovered service.</returns>
        public static Uri GetServiceEndpointFromDnsConvention(string serviceName = null, string appKey = null,
            string locationKey = null)
        {
            var formatter = new DnsServiceEndpointFormatter();
            return formatter.Format(appKey, serviceName, locationKey);
        }

        /// <summary>
        ///     Get a certificate from a certificate store by thumbprint.
        /// </summary>
        /// <param name="thumbprint">The thumbprint of the certificate.</param>
        /// <param name="storeName">The name of the store to look for the certificate.</param>
        /// <param name="storeLocation">The location of the store to look for the certificate.</param>
        /// <returns> The matching <see cref="X509Certificate2" />, or <c>null</c> if no matching certificate found.</returns>
        public static X509Certificate2 GetCertificateByThumbprint(string thumbprint, StoreName storeName = StoreName.My,
            StoreLocation storeLocation = StoreLocation.LocalMachine)
        {
            Check.ArgumentNotNullOrWhiteSpace(thumbprint, nameof(thumbprint));

            using (var store = new X509Store(storeName, storeLocation))
            {
                store.Open(OpenFlags.ReadOnly);
                var certificates = store.Certificates.Find(X509FindType.FindByThumbprint, thumbprint, false);
                if (certificates.Count == 0) return null;

                return certificates[0];
            }
        }

        /// <summary>
        ///     Get a certificate from a base64 encoded string.
        /// </summary>
        /// <param name="encodedCert">The base64 encoded certificate.</param>
        /// <returns> The decoded <see cref="X509Certificate2" />.</returns>
        public static X509Certificate2 GetCertificateByEncodedString(string encodedCert)
        {
            Check.ArgumentNotNullOrWhiteSpace(encodedCert, nameof(encodedCert));

            var rawCertificate = Convert.FromBase64String(encodedCert);
            return new X509Certificate2(rawCertificate);
        }
    }
}