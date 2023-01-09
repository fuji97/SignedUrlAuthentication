using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using SignedUrlAuthentication.Services;
namespace SignedUrlAuthentication.Controllers; 

[ApiController]
[Route("[controller]")]
public class SignedUrlController : ControllerBase {
    private readonly ISignedUrlService _signedUrlService;
    
    public SignedUrlController(ISignedUrlService signedUrlService) {
        _signedUrlService = signedUrlService;
    }
    
    [HttpGet("/get")]
    public IActionResult GetUrl(string principal, int expirationSeconds) {
        var url = Url.ActionLink("TestUrl");
        var signedUrl = _signedUrlService.SignUrl(url!, principal, TimeSpan.FromSeconds(expirationSeconds));
        
        return Ok(signedUrl.ToString());
    }
    
    [Authorize]
    [HttpGet("/private")]
    public IActionResult TestUrl() {
        var principal = HttpContext.User.Identity?.Name;
        return Ok("Hello, " + principal);
    }
}
