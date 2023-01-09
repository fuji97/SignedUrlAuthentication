namespace SignedUrlAuthentication.Models; 

public class SignedUrlResult {
    public bool IsValid { get; set; }
    public SignedUrlToken? Token { get; set; }
    public string? ErrorMessage { get; set; }
    
    public static SignedUrlResult Invalid(string errorMessage) {
        return new SignedUrlResult {
            IsValid = false,
            ErrorMessage = errorMessage
        };
    }
    
    public static SignedUrlResult Valid(SignedUrlToken token) {
        return new SignedUrlResult {
            IsValid = true,
            Token = token
        };
    }
}