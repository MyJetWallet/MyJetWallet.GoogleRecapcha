using System.Net;
using System.Net.Http.Json;
using Newtonsoft.Json;

namespace MyJetWallet.GoogleRecaptcha;

public class ReCaptchaServer: IDisposable, IReCaptchaServer
{
    private string _securityKey;
    private readonly float _minScore;
    private readonly string _allowAlwaysCode;

    public ReCaptchaServer(string securityKey, float minScore, string allowAlwaysCode)
    {
        _securityKey = securityKey;
        _minScore = minScore;
        _allowAlwaysCode = allowAlwaysCode;
    }

    public async Task<ValidateTokenResponse> ValidateTokenAsync(string token ,string clientIp)
    {
        if (!string.IsNullOrEmpty(_allowAlwaysCode) && token == _allowAlwaysCode)
        {
            return new ValidateTokenResponse()
            {
                Success = true,
                Error = "Internal allow",
                StatusCode = HttpStatusCode.OK
            };
        }
        
        var dictionary = new Dictionary<string, string>
        {
            { "secret", _securityKey },
            { "response", token }
        };
        if (!string.IsNullOrEmpty(clientIp))
        {
            dictionary["remoteip"] = clientIp;
        }
        
        var postContent = new FormUrlEncodedContent(dictionary);
         
        using var client = new HttpClient();
        
        var resp = await client.PostAsync("https://www.google.com/recaptcha/api/siteverify", postContent);

        var stringContent = await resp.Content.ReadAsStringAsync();
        
        if (!resp.IsSuccessStatusCode)
        {
            return new ValidateTokenResponse()
            {
                Success = false,
                Error = $"Cannot execute GoogleRecaptcha Validation, StatusCode: {resp.StatusCode}",
                StatusCode = resp.StatusCode,
                HttpResponseBody = stringContent
            };
        }
        
        if (string.IsNullOrEmpty(stringContent))
        {
            return new ValidateTokenResponse()
            {
                Success = false,
                Error = $"Invalid google reCAPTCHA verification response: {resp.StatusCode}",
                StatusCode = resp.StatusCode,
                HttpResponseBody = stringContent
            };
        }
        
        var reCaptchaResponse = JsonConvert.DeserializeObject<ReCaptchaResponse>(stringContent);

        if (reCaptchaResponse == null)
        {
            return new ValidateTokenResponse()
            {
                Success = false,
                Error = $"Invalid google reCAPTCHA verification response (cannot parse): {resp.StatusCode}",
                StatusCode = resp.StatusCode,
                HttpResponseBody = stringContent
            };
        }
        
        if (!reCaptchaResponse.Success)
        {

            var errors = string.Join(",", reCaptchaResponse.ErrorCodes ?? new string[] {});

            return new ValidateTokenResponse()
            {
                Success = false,
                Error = errors,
                StatusCode = resp.StatusCode,
                HttpResponseBody = stringContent,
                Response = reCaptchaResponse
            };
        }
        
        if (reCaptchaResponse.Score < _minScore)
        {
            return new ValidateTokenResponse()
            {
                Success = false,
                Error = $"It might be a boat. Bad score: {reCaptchaResponse.Score}",
                StatusCode = resp.StatusCode,
                HttpResponseBody = stringContent,
                Response = reCaptchaResponse
            };
        }
        
        return new ValidateTokenResponse()
        {
            Success = true,
            Error = String.Empty,
            StatusCode = resp.StatusCode,
            HttpResponseBody = stringContent,
            Response = reCaptchaResponse
        };
    }

    public void Dispose()
    {
    }
}

public class ValidateTokenResponse
{
    public bool Success { get; set; }
    
    public string? Error { get; set; }
    
    public HttpStatusCode StatusCode { get; set; }
    
    public string? HttpResponseBody { get; set; }
    
    public ReCaptchaResponse? Response { get; set; }
}