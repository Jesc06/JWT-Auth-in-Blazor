# JWT-Auth-in-Blazor
*JWT Auth Configuration in Blazor*


1. *Create base URL API in blazor client side*

   ```csharp
    builder.Services.AddHttpClient("API", option =>
    { 
        option.BaseAddress = new Uri("https://localhost:7253");
    } );
   ```
   *https://localhost:7253 is Web API localhost URL*

<br>


2. *Create LoginDTO & JwtTokenDTO*
   
   *LoginDTO*
   ```csharp
   using System;
   using System.Collections.Generic;
   using System.ComponentModel.DataAnnotations;
   using System.Linq;
   using System.Threading.Tasks;
   
   namespace RecordManagementSystemClientSide.DTO
   {
       public class LoginDTO
       {
           [EmailAddress(ErrorMessage = "Invalid email format")]
           public string email { get; set; } 
           
           [Required(ErrorMessage = "Please input your password")]
           public string password { get; set; }
       }
   }
   ```

      *JwtTokenDTO*
   ```csharp
   using System;
   using System.Collections.Generic;
   using System.Linq;
   using System.Threading.Tasks;
   
   namespace RecordManagementSystemClientSide.DTO
   {
       public class JwtToken
       {
           public string Token { get; set; }
           public string RefreshToken { get; set; }
           public DateTime RefreshTokenExpiry { get; set; }
           public int ExpiresIn { get; set; }
       }
   }
   ```

   


<br>

3. *Create a Services folder and create a AuthSerices.cs file*

![Step 1](Services.png)

```csharp
using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using RecordManagementSystemClientSide.DTO;
using System.Net.Http.Json;
using Microsoft.JSInterop;
using System.Net.Http.Headers;


namespace RecordManagementSystemClientSide.Services
{
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

        public async Task<string> login(LoginDTO loginDto)
        {
            var http = _httpClientFactory.CreateClient("API");
            var response = await http.PostAsJsonAsync("api/LoginRegister/Login", loginDto);

            if (response.IsSuccessStatusCode)
            {
                var result = await response.Content.ReadFromJsonAsync<JwtToken>();

                await _jsRuntime.InvokeVoidAsync("localStorage.setItem", "authToken", result.Token);
                await _jsRuntime.InvokeVoidAsync("localStorage.setItem", "refreshToken", result.RefreshToken);
                await _jsRuntime.InvokeVoidAsync("localStorage.setItem", "tokenExpiry", DateTime.UtcNow.AddSeconds(result.ExpiresIn).ToString("o"));

                _httpClient.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", result.Token);
                return result.Token;
            }
            return null;
        }


        public async Task EnsureValidToken()
        {
            var expiryStr = await _jsRuntime.InvokeAsync<string>("localStorage.getItem", "refreshToken");
            if (!DateTime.TryParse(expiryStr, out var expiry)) return;
            if (DateTime.UtcNow >= expiry)
            {
                var refreshToken = await _jsRuntime.InvokeAsync<string>("localStorage.getItem", "refreshToken");
                if (string.IsNullOrWhiteSpace(refreshToken)) return;

                var http = _httpClientFactory.CreateClient("API");
                var refreshResponse = await http.PostAsJsonAsync("api/LoginRegister/Refresh Token", new { RefreshToken = refreshToken });

                if (refreshResponse.IsSuccessStatusCode)
                {
                    var result = await refreshResponse.Content.ReadFromJsonAsync<JwtToken>();
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
        }


    }
}
```

<br>

4. *Create CustomAuthProvider for handling authorization, Login, Logout*

   ```csharp
   using System;
   using System.Collections.Generic;
   using System.Linq;
   using System.Runtime.CompilerServices;
   using System.Runtime.InteropServices.JavaScript;
   using System.Security.Claims;
   using System.Text.Json;
   using System.Threading.Tasks;
   using Microsoft.AspNetCore.Components.Authorization;
   using Microsoft.JSInterop;
   
   namespace RecordManagementSystemClientSide.Security
   {
       public class CustomAuthProvider : AuthenticationStateProvider
       {
           private readonly IJSRuntime _jsRuntime;
           public CustomAuthProvider(IJSRuntime jsRuntime)
           {
               _jsRuntime = jsRuntime;
           }

        public override async Task<AuthenticationState> GetAuthenticationStateAsync()
        {
            var token = await _jsRuntime.InvokeAsync<string>("localStorage.getItem", "authToken");

            if (string.IsNullOrWhiteSpace(token))
            {
                return new AuthenticationState(new ClaimsPrincipal(new ClaimsIdentity()));
            }

            var claims = ParseClaimsFromJwt(token);
            var identity = new ClaimsIdentity(claims, "Jwt");
            var user = new ClaimsPrincipal(identity);
            return new AuthenticationState(user);
        }


        public void NotifyUserAuthentication(string token)
        {
            var claims = ParseClaimsFromJwt(token);
            var authenticatedUser = new ClaimsPrincipal(new ClaimsIdentity(claims, "Jwt"));
            var authState = Task.FromResult(new AuthenticationState(authenticatedUser));
            NotifyAuthenticationStateChanged(authState);
        }

        public void NotifyLogout()
        {
            var authState = Task.FromResult(new AuthenticationState(new ClaimsPrincipal(new ClaimsIdentity())));
            NotifyAuthenticationStateChanged(authState);
        }

        private IEnumerable<Claim> ParseClaimsFromJwt(string jwt)
        {
            var payload = jwt.Split('.')[1];
            var jsonBytes = ParseBase64WithoutPadding(payload);

            var claims = new List<Claim>();
            using var doc = JsonDocument.Parse(jsonBytes);
            foreach (var kvp in doc.RootElement.EnumerateObject())
            {
                // Kung number, gawin string representation
                if (kvp.Value.ValueKind == JsonValueKind.Number)
                {
                    claims.Add(new Claim(kvp.Name, kvp.Value.GetRawText()));
                }
                else
                {
                    claims.Add(new Claim(kvp.Name, kvp.Value.ToString()));
                }
            }

            return claims;
        }



        private byte[] ParseBase64WithoutPadding(string base64)
        {
            switch (base64.Length % 4)
            {
                case 2: base64 += "=="; break;
                case 3: base64 += "="; break;
            }
            return Convert.FromBase64String(base64);
        }

        
        
     }
   }
   ```

5. *Actual Implementation in Login UI*
  
      ```csharp
      @inject AuthenticationStateProvider authProvider
      @inject AuthService authService
      
      @code{
          LoginDTO loginDTO = new();
      
          protected override async Task OnInitializedAsync(){
              await authService.EnsureValidToken();
              var auth = await authProvider.GetAuthenticationStateAsync();
              if(auth.User.Identity?.IsAuthenticated == true){
                  nav.NavigateTo("/Tama");
              }
          }
          
          public async Task SuccessllyValid(){
              var token = await authService.login(loginDTO);
              if(!string.IsNullOrWhiteSpace(token)){
                  ((CustomAuthProvider)authProvider).NotifyUserAuthentication(token);
                  nav.NavigateTo("/Tama");
              } 
              else{
                  nav.NavigateTo("/Mali");
              }
          }
       
      }



      ```

      <br>

6 *Register Services & CustomAuthProvider in Program.cs*

```csharp

builder.Services.AddScoped<AuthService>();
builder.Services.AddScoped<AuthenticationStateProvider, CustomAuthProvider>();
builder.Services.AddAuthorizationCore();

```
      
