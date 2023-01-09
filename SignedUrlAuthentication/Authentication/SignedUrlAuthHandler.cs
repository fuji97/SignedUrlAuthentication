using System.Security.Claims;
using System.Text.Encodings.Web;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Http.Extensions;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Options;
using SignedUrlAuthentication.Services;
namespace SignedUrlAuthentication.Authentication; 

public class SignedUrlAuthHandler : AuthenticationHandler<SignedUrlAuthSchemeOptions> {
    private readonly ISignedUrlService _signedUrlService;
    
    public SignedUrlAuthHandler(
        IOptionsMonitor<SignedUrlAuthSchemeOptions> options, 
        ILoggerFactory logger, 
        UrlEncoder encoder, 
        ISystemClock clock, ISignedUrlService signedUrlService) : base(options, logger, encoder, clock) {
        _signedUrlService = signedUrlService;
    }
    protected override async Task<AuthenticateResult> HandleAuthenticateAsync() {
        if (!Context.Request.Query.TryGetValue("token", out var token) || string.IsNullOrEmpty(token)) {
            return AuthenticateResult.Fail("No token provided");
        }

        string url = $"{Request.Scheme}://{Request.Host}{Request.PathBase}{Request.Path}";
        
        var result = _signedUrlService.ValidateToken(url , token);
        if (result.IsValid) {
            var claim = new Claim(ClaimTypes.Name, result.Token!.Principal);
            var identity = new ClaimsIdentity(new[] { claim }, "SignedUrl");
            var principal = new ClaimsPrincipal(identity);
            var ticket = new AuthenticationTicket(principal, Scheme.Name);
            return AuthenticateResult.Success(ticket);
        }
        else {
            return AuthenticateResult.Fail(result.ErrorMessage!);
        }
    }
}
