namespace MyJetWallet.GoogleRecaptcha;

public interface IReCaptchaServer
{
    Task<ValidateTokenResponse> ValidateTokenAsync(string token ,string clientIp);
}