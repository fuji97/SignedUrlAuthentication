using Flurl;
using SignedUrlAuthentication.Models;
namespace SignedUrlAuthentication.Services; 

public static class SignedUrlServiceExtensions {
    public static string GenerateToken(this ISignedUrlService service, string url, string principal, TimeSpan expiration) {
        var currentTime = DateTimeOffset.UtcNow;
        return service.GenerateToken(new SignedUrlToken() {
            Url = url, Principal = principal, CreationTime = currentTime.ToUnixTimeSeconds(), ExpirationTime = currentTime.Add(expiration).ToUnixTimeSeconds()
        });
    }
    
    public static Url SignUrl(this ISignedUrlService service, Url url, string principal, TimeSpan expiration) {
        return url.SetQueryParam("token", service.GenerateToken(url.SetQueryParams(null).ToString(), principal, expiration));
    }

    public static Url SignUrl(this ISignedUrlService service, string url, string principal, TimeSpan expiration) {
        return SignUrl(service, Url.Parse(url), principal, expiration);
    }
}
