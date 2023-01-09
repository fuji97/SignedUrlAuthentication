namespace SignedUrlAuthentication.Services; 

public class SignedUrlOptions {
    public const string SignedUrlOptionsKey = "SignedUrl";
    
    public string Key { get; } = string.Empty;
}
