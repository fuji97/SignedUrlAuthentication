using SignedUrlAuthentication.Models;
namespace SignedUrlAuthentication.Services; 

public interface ISignedUrlService {
    string GenerateToken(SignedUrlToken token);
    SignedUrlResult ValidateToken(string url, string token);
}