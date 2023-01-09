using System.Net;
using System.Security.Cryptography;
using System.Text;
using System.Text.Encodings.Web;
using System.Text.RegularExpressions;
using Microsoft.AspNetCore.WebUtilities;
using Microsoft.Extensions.Options;
using SignedUrlAuthentication.Models;
namespace SignedUrlAuthentication.Services;

class SignedUrlService : ISignedUrlService {
    private readonly SignedUrlOptions _options;
    private readonly ILogger<SignedUrlService> _logger;

    private static Regex _principalRegex = new Regex(@"^[^;]+$");
    private static Regex _tokenRegex = new Regex(@"^(?<token>(?<url>.+);(?<principal>.+?);(?<creationTime>\d+?);(?<absoluteExpireTime>\d+?));(?<signature>(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?)$");

    public SignedUrlService(IOptions<SignedUrlOptions> options, ILogger<SignedUrlService> logger) {
        _logger = logger;
        _options = options.Value;
    }
    
    public string GenerateToken(SignedUrlToken token) {
        var key = _options.Key;
        if (!_principalRegex.IsMatch(token.Principal)) {
            throw new ArgumentException("Invalid principal");
        }
        // var currentTime = DateTimeOffset.UtcNow;
        // var absoluteExpireTime = currentTime.Add(expiration).ToUnixTimeSeconds();
        var stringToken = $"{token.Url};{token.Principal};{token.CreationTime};{token.ExpirationTime}";
        var signature = Convert.ToBase64String(Sign(stringToken, key));
        
        return Convert.ToBase64String(Encoding.UTF8.GetBytes($"{stringToken};{signature}"));
    }
    public SignedUrlResult ValidateToken(string url, string signedToken) {
        var convertedToken = Encoding.UTF8.GetString(Convert.FromBase64String(signedToken));
        
        var match = _tokenRegex.Match(convertedToken);
        
        // Check if the token parsing is valid
        if (!match.Success) {
            return SignedUrlResult.Invalid("Error parsing signed token");
        }
        
        // Get values
        var key = _options.Key;
        var currentTime = DateTimeOffset.UtcNow;
        var token = match.Groups["token"].Value;
        var tokenUrl = match.Groups["url"].Value;
        var tokenPrincipal = match.Groups["principal"].Value;
        var tokenCreationTime = DateTimeOffset.FromUnixTimeSeconds(long.Parse(match.Groups["creationTime"].Value));
        var tokenAbsoluteExpireTime = DateTimeOffset.FromUnixTimeSeconds(long.Parse(match.Groups["absoluteExpireTime"].Value));
        var tokenSignature = match.Groups["signature"].Value;
        
        // Check if signature is valid
        if (!Sign(token, key).SequenceEqual(Convert.FromBase64String(tokenSignature))) {
            return SignedUrlResult.Invalid("Invalid signature");
        }
        
        // Check if the token creation date is valid
        if (tokenCreationTime > currentTime) {
            return SignedUrlResult.Invalid("Token creation date is in the future");
        }
        
        // Check if the token expiration date is valid
        if (tokenAbsoluteExpireTime < currentTime) {
            return SignedUrlResult.Invalid("Token has expired");
        }
        
        // Check if the token url is valid
        if (tokenUrl != url) {
            return SignedUrlResult.Invalid("Token url is invalid");
        }

        return SignedUrlResult.Valid(new SignedUrlToken() {
            CreationTime = tokenCreationTime.ToUnixTimeSeconds(),
            ExpirationTime = tokenAbsoluteExpireTime.ToUnixTimeSeconds(),
            Principal = tokenPrincipal,
            Url = tokenUrl
        });
    }
    
    private byte[] Sign(string token, string key) {
        var data = Encoding.UTF8.GetBytes(token).Concat(Encoding.UTF8.GetBytes(key)).ToArray();
        var hashstring = SHA256.HashData(data);
        return hashstring;
    }
}
