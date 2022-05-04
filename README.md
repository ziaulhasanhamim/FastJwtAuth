# FastAuthJwt
Quickly implement Authentication in your app with Json Web tokens and refresh token

### Basic Usage using Ef Core

You should first install [FastJwtAuth.EFCore](https://www.nuget.org/packages/FastJwtAuth.EFCore/):

    dotnet add package FastJwtAuth.EFCore
    
Then configure you database using ef core as your needs. In the OnModelCreating method in DbContext class call the ConfigureAuthModels extension method

```csharp
using FastJwtAuth;
using FastJwtAuth.EFCore;

....

public class ApplicationDbContext : DbContext
{
    private readonly FastAuthOptions _authOptions;

    public ApplicationDbContext(DbContextOptions<ApplicationDbContext> options, FastAuthOptions authOptions)
        : base(options)
    {
        _authOptions = authOptions;
    }

    public DbSet<FastUser> Users { get; set; } // optional

    public DbSet<FastRefreshToken> RefreshTokens { get; set; } // optional

    protected override void OnModelCreating(ModelBuilder modelBuilder)
    {
        modelBuilder.ConfigureAuthModels(_authOptions);
        base.OnModelCreating(modelBuilder);
    }
}

```

Then configure the services for fastjwtauth

```csharp
using FastJwtAuth;
using FastJwtAuth.EFCore;

....

public class Startup
{
    ....

    public void ConfigureServices(IServiceCollection services)
    {
        services.AddDbContext<ApplicationDbContext>(
            options => options.UseSqlite("DataSource=App.db"));

        services.AddControllers();

        services.AddSwaggerGen(options =>
        {
            options.SwaggerDoc("v1", new OpenApiInfo { Title = "GettingStarted-EFCore", Version = "v1" });

            options.AddSecurityDefinition("Bearer", new OpenApiSecurityScheme()
            {
                Name = "Authorization",
                Type = SecuritySchemeType.ApiKey,
                In = ParameterLocation.Header,
                Description = "JWT Authorization header using the Bearer scheme. \r\n\r\n Enter 'Bearer' [space] and then your token in the text input below.\r\n\r\nExample: \"Bearer 12345abcdef\"",
            });

            OpenApiSecurityRequirement securityRequirement = new();
            securityRequirement.Add(new OpenApiSecurityScheme
            {
                Reference = new OpenApiReference
                {
                    Type = ReferenceType.SecurityScheme,
                    Id = "Bearer"
                },
            }, new string[0]);

            options.AddSecurityRequirement(securityRequirement);
        }); // for swagger support

        services.AddAuthentication("JwtAuth")
            .AddJwtBearer("JwtAuth", options =>
            {
                options.TokenValidationParameters = new()
                {
                    ValidateIssuer = false,
                    ValidateAudience = false,
                    ValidateLifetime = true,
                    ValidateIssuerSigningKey = true,
                    IssuerSigningKey = new SymmetricSecurityKey(
                        Encoding.Unicode.GetBytes("123456789abcdefgfhijklmnopqrstuvwxyz"))
                };
                options.MapInboundClaims = false; // important
            }); // jwt token authorization

        services.AddFastAuthWithEFCore<ApplicationDbContext>(options =>
        {
            options.UseRefreshToken = true;
            options.UseDefaultCredentials("123456789abcdefgfhijklmnopqrstuvwxyz");
        }); // Default user auth setup with refresh token
    }

    public void Configure(IApplicationBuilder app, IWebHostEnvironment env)
    {
        ....

        app.UseAuthentication(); // important
        app.UseAuthorization(); // important

        ....
    }
}

```

Now add the controllers for authentication

```csharp
using FastJwtAuth;
using FastJwtAuth.EFCore;

....

[Route("/api/[controller]/")]
[ApiController]
public class AuthenticationController : ControllerBase
{
    private readonly IFastAuthService _authService;

    public AuthenticationController(IFastAuthService authService)
    {
        _authService = authService;
    }

    [HttpPost("create-user")]
    public async Task<IActionResult> CreateUser([FromBody] CreateUserRequest request)
    {
        FastUser user = new()
        {
            Email = request.Email
        };
        var createResult = await _authService.CreateUserAsync(user, request.Password);
        if (!createResult.Success)
        {
            return BadRequest(createResult);
        }
        var authResult = await _authService.AuthenticateAsync(user);
        AuthResponse authRes = new(authResult.AccessToken, authResult.RefreshToken);
        return Ok(authRes);
    }

    [HttpPost("login")]
    public async Task<IActionResult> LoginUser([FromBody] LoginUserRequest request)
    {
        var authResult = await _authService.AuthenticateAsync(request.Email, request.Password);
        if (authResult is AuthResult<FastUser>.Success successResult)
        {
            AuthResponse authRes = new(successResult.AccessToken, successResult.RefreshToken);
            return Ok(authRes);
        }
        return BadRequest(authResult);
    }

    [HttpPost("refresh")]
    public async Task<IActionResult> Refresh([FromBody] string refreshToken)
    {
        var authResult = await _authService.RefreshAsync(refreshToken);
        if (authResult is AuthResult<FastUser>.Success successResult)
        {
            AuthResponse authRes = new(successResult.AccessToken, successResult.RefreshToken);
            return Ok(authRes);
        }
        return BadRequest(authResult);
    }

    [HttpGet("authorize")]
    [Authorize]
    public IActionResult Authorize()
    {
        var user = User.MapClaimsToFastUser();
        UserResponse res = new(
            user.Id,
            user.Email,
            user.CreatedAt);
        return Ok(res);
    }
}

```
Now finally you can run your app. All The codes available [here](https://github.com/ziaulhasanhamim/FastJwtAuth/tree/main/examples/GettingStarted-EFCore)
