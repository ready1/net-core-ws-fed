using System;
using System.Collections.Generic;
using System.Linq;
using System.Net.Http;
using System.Threading.Tasks;
using Microsoft.IdentityModel.Tokens;
using Newtonsoft.Json;

namespace AuthTest2.Models
{
    public static class OAuth2Request
    {
        public static FormUrlEncodedContent GetOAuth2RequestContent(string grantType, string samlAssertion)
        {
            var encodedToken = Base64UrlEncoder.Encode(samlAssertion);
            return new FormUrlEncodedContent(new[]
            {
                new KeyValuePair<string, string>("grant_type", grantType),
                new KeyValuePair<string, string>("assertion", encodedToken)
            });
        }
    }

    public class OAuth2ResponseModel
    {
        [JsonProperty("access_token")]
        public string AccessToken { get; set; }

        [JsonProperty("token_type")]
        public string TokenType { get; set; }

        [JsonProperty("expires_in")]
        public int ExpiresIn { get; set; }
    }
}
