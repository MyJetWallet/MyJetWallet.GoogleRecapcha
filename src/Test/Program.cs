// See https://aka.ms/new-console-template for more information

using MyJetWallet.GoogleRecaptcha;
using Newtonsoft.Json;

var service = new ReCaptchaServer("SECRET_KEY", 0.5f, string.Empty, string.Empty);


var resp = await service.ValidateTokenAsync(
    "token",
    "action");

Console.WriteLine(JsonConvert.SerializeObject(resp, Formatting.Indented));

Console.ReadKey();