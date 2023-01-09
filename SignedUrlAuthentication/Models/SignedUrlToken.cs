namespace SignedUrlAuthentication.Models; 

public record SignedUrlToken {
    public string Url { get; init; } = string.Empty;
    public string Principal { get; init; } = string.Empty;
    public long CreationTime { get; init; }
    public long ExpirationTime { get; init; }
}
