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

2. Create a Services folder and create a AuthSerices.cs file
      
