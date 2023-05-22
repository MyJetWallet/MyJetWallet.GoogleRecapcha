using System.Net;
using Newtonsoft.Json;

namespace MyJetWallet.GoogleRecaptcha;

public class ReCaptchaServer: IDisposable, IReCaptchaServer
{
    private string _securityKey;
    private readonly float _minScore;
    private readonly string _allowAlwaysCode;
    private readonly string _allowHost;

    public ReCaptchaServer(string securityKey, float minScore, string allowAlwaysCode, string allowHost)
    {
        _securityKey = securityKey;
        _minScore = minScore;
        _allowAlwaysCode = allowAlwaysCode;
        _allowHost = allowHost;
    }

    public async Task<ValidateTokenResponse> ValidateTokenAsync(string token, string action)
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
        
        if (!string.IsNullOrEmpty(_allowHost) && reCaptchaResponse.Hostname != _allowHost)
        {
            return new ValidateTokenResponse()
            {
                Success = false,
                Error = $"It might be a boat. Bad host: {reCaptchaResponse.Hostname}",
                StatusCode = resp.StatusCode,
                HttpResponseBody = stringContent,
                Response = reCaptchaResponse
            };
        }
        
        if (!string.IsNullOrEmpty(action) && reCaptchaResponse.Action != action)
        {
            return new ValidateTokenResponse()
            {
                Success = false,
                Error = $"It might be a boat. Bad action: {reCaptchaResponse.Action}, Expected: {action}",
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