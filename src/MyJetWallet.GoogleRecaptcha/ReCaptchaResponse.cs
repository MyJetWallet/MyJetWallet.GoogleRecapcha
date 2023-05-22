using Newtonsoft.Json;

namespace MyJetWallet.GoogleRecaptcha;

public class ReCaptchaResponse
{
    [JsonProperty("success")]
    public bool Success { get; set; }

    [JsonProperty("score")]
    public float Score { get; set; } 
    
    [JsonProperty("action")]
    public string Action { get; set; } 
    
    [JsonProperty("challenge_ts")]
    public DateTime Timestamp { get; set; } 
    
    [JsonProperty("hostname")]
    public string Hostname { get; set; }

    [JsonProperty("error-codes")]
    public string[] ErrorCodes { get; set; }
}