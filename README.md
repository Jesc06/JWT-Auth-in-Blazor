# 🔑 JWT Authentication in Blazor (Client-Side)

**[Web API JWT Configuration](https://github.com/Jesc06/ASP.NET-Core-Empty-MVC-set-up.git)**  
You can check out this repository for more info on how to configure JWT authentication in a Web API.

---

This guide explains how to **connect Blazor WebAssembly** with a **JWT-secured ASP.NET Core Web API**.  
Includes **token storage**, **refresh token handling**, and **authentication state management**. 🚀

---

## 1️⃣ Configure Base API URL

Add the base address for your Web API in `Program.cs`:

```csharp
builder.Services.AddHttpClient("API", option =>
{
    option.BaseAddress = new Uri("https://localhost:7253");
});
```

> 📝 Replace `https://localhost:7253` with your Web API URL.

---

## 2️⃣ Create DTOs

### `LoginDTO.cs`

```csharp
using System.ComponentModel.DataAnnotations;

namespace RecordManagementSystemClientSide.DTO;

public class LoginDTO
{
    [EmailAddress(ErrorMessage = "Invalid email format")]
    public string email { get; set; }

    [Required(ErrorMessage = "Please input your password")]
    public string password { get; set; }
}
```

### `JwtToken.cs`

```csharp
namespace RecordManagementSystemClientSide.DTO;

public class JwtToken
{
    public string Token { get; set; }
    public string RefreshToken { get; set; }
    public DateTime RefreshTokenExpiry { get; set; }
    public int ExpiresIn { get; set; }
}
```

---

## 3️⃣ Create `AuthService`

📂 **Create a `Services` folder** and add `AuthService.cs`:

```csharp
using System.Net.Http.Json;
using System.Net.Http.Headers;
using Microsoft.JSInterop;
using RecordManagementSystemClientSide.DTO;

namespace RecordManagementSystemClientSide.Services;

public class AuthService
{
    private readonly HttpClient _httpClient;
    private readonly IHttpClientFactory _httpClientFactory;
    private readonly IJSRuntime _jsRuntime;

    public AuthService(HttpClient httpClient, IHttpClientFactory httpClientFactory, IJSRuntime jsRuntime)
    {
        _httpClient = httpClient;
        _httpClientFactory = httpClientFactory;
        _jsRuntime = jsRuntime;
    }

    public async Task<string?> Login(LoginDTO loginDto)
    {
        var http = _httpClientFactory.CreateClient("API");
        var response = await http.PostAsJsonAsync("api/LoginRegister/Login", loginDto);

        if (!response.IsSuccessStatusCode) return null;

        var result = await response.Content.ReadFromJsonAsync<JwtToken>();
        if (result is null) return null;

        await _jsRuntime.InvokeVoidAsync("localStorage.setItem", "authToken", result.Token);
        await _jsRuntime.InvokeVoidAsync("localStorage.setItem", "refreshToken", result.RefreshToken);
        await _jsRuntime.InvokeVoidAsync("localStorage.setItem", "tokenExpiry", DateTime.UtcNow.AddSeconds(result.ExpiresIn).ToString("o"));

        _httpClient.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", result.Token);
        return result.Token;
    }

    public async Task EnsureValidToken()
    {
        var expiryStr = await _jsRuntime.InvokeAsync<string>("localStorage.getItem", "tokenExpiry");
        if (!DateTime.TryParse(expiryStr, out var expiry)) return;

        if (DateTime.UtcNow >= expiry)
        {
            var refreshToken = await _jsRuntime.InvokeAsync<string>("localStorage.getItem", "refreshToken");
            if (string.IsNullOrWhiteSpace(refreshToken)) return;

            var http = _httpClientFactory.CreateClient("API");
            var refreshResponse = await http.PostAsJsonAsync("api/LoginRegister/RefreshToken", new { RefreshToken = refreshToken });

            if (refreshResponse.IsSuccessStatusCode)
            {
                var result = await refreshResponse.Content.ReadFromJsonAsync<JwtToken>();
                if (result is null) return;

                await _jsRuntime.InvokeVoidAsync("localStorage.setItem", "authToken", result.Token);
                await _jsRuntime.InvokeVoidAsync("localStorage.setItem", "refreshToken", result.RefreshToken);
                await _jsRuntime.InvokeVoidAsync("localStorage.setItem", "tokenExpiry", DateTime.UtcNow.AddSeconds(result.ExpiresIn).ToString("o"));

                _httpClient.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", result.Token);
            }
            else
            {
                await Logout();
            }
        }
    }

    public async Task Logout()
    {
        var http = _httpClientFactory.CreateClient("API");
        await http.PostAsync("api/Account/Logout", null);
        await _jsRuntime.InvokeVoidAsync("localStorage.removeItem", "authToken");
        await _jsRuntime.InvokeVoidAsync("localStorage.removeItem", "refreshToken");
        await _jsRuntime.InvokeVoidAsync("localStorage.removeItem", "tokenExpiry");
    }
}
```

---

## 4️⃣ Create `CustomAuthProvider`

Handles user claims and authentication state:

```csharp
using System.Security.Claims;
using System.Text.Json;
using Microsoft.AspNetCore.Components.Authorization;
using Microsoft.JSInterop;

namespace RecordManagementSystemClientSide.Security;

public class CustomAuthProvider : AuthenticationStateProvider
{
    private readonly IJSRuntime _jsRuntime;

    public CustomAuthProvider(IJSRuntime jsRuntime) => _jsRuntime = jsRuntime;

    public override async Task<AuthenticationState> GetAuthenticationStateAsync()
    {
        var token = await _jsRuntime.InvokeAsync<string>("localStorage.getItem", "authToken");
        if (string.IsNullOrWhiteSpace(token))
            return new AuthenticationState(new ClaimsPrincipal(new ClaimsIdentity()));

        var claims = ParseClaimsFromJwt(token);
        var identity = new ClaimsIdentity(claims, "Jwt");
        return new AuthenticationState(new ClaimsPrincipal(identity));
    }

    public void NotifyUserAuthentication(string token)
    {
        var claims = ParseClaimsFromJwt(token);
        var authState = Task.FromResult(new AuthenticationState(new ClaimsPrincipal(new ClaimsIdentity(claims, "Jwt"))));
        NotifyAuthenticationStateChanged(authState);
    }

    public void NotifyLogout()
    {
        var authState = Task.FromResult(new AuthenticationState(new ClaimsPrincipal(new ClaimsIdentity())));
        NotifyAuthenticationStateChanged(authState);
    }

    private static IEnumerable<Claim> ParseClaimsFromJwt(string jwt)
    {
        var payload = jwt.Split('.')[1];
        var jsonBytes = ParseBase64WithoutPadding(payload);

        using var doc = JsonDocument.Parse(jsonBytes);
        return doc.RootElement.EnumerateObject()
            .Select(kvp => new Claim(kvp.Name,
                kvp.Value.ValueKind == JsonValueKind.Number ? kvp.Value.GetRawText() : kvp.Value.ToString()));
    }

    private static byte[] ParseBase64WithoutPadding(string base64)
    {
        switch (base64.Length % 4)
        {
            case 2: base64 += "=="; break;
            case 3: base64 += "="; break;
        }
        return Convert.FromBase64String(base64);
    }
}
```

---

## 5️⃣ Use in Login Component

```razor
@inject AuthenticationStateProvider authProvider
@inject AuthService authService
@inject NavigationManager nav

<LoginForm Model="loginDTO" OnValidSubmit="HandleLogin" />

@code {
    LoginDTO loginDTO = new();

    protected override async Task OnInitializedAsync()
    {
        await authService.EnsureValidToken();
        var auth = await authProvider.GetAuthenticationStateAsync();
        if (auth.User.Identity?.IsAuthenticated == true)
            nav.NavigateTo("/Tama");
    }

    private async Task HandleLogin()
    {
        var token = await authService.Login(loginDTO);
        if (!string.IsNullOrWhiteSpace(token))
        {
            ((CustomAuthProvider)authProvider).NotifyUserAuthentication(token);
            nav.NavigateTo("/Tama");
        }
        else
        {
            nav.NavigateTo("/Mali");
        }
    }
}
```

---

## 6️⃣ Register Services in `Program.cs`

```csharp
builder.Services.AddScoped<AuthService>();
builder.Services.AddScoped<AuthenticationStateProvider, CustomAuthProvider>();
builder.Services.AddAuthorizationCore();
```

✅ Your Blazor app is now connected to your API with **JWT + Refresh Token support**.
