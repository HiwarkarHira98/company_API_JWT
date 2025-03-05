using CompanyWebApi;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using CompanyApiJwt.Model;
using System.Text;

var builder = WebApplication.CreateBuilder(args);
var key = Encoding.ASCII.GetBytes("YourSecretKeyHere");

// Add JWT Authentication
builder.Services.AddAuthentication(JwtBearerDefaults.AuthenticationScheme)
    .AddJwtBearer(options =>
    {
        options.RequireHttpsMetadata = false;
        options.SaveToken = true;
        options.TokenValidationParameters = new TokenValidationParameters
        {
            ValidateIssuerSigningKey = true,
            IssuerSigningKey = new SymmetricSecurityKey(key),
            ValidateIssuer = false,
            ValidateAudience = false
        };
    });

builder.Services.AddAuthorization();
var app = builder.Build();

// Login Endpoint
app.MapPost("/login", ([FromBody] LoginModel login) =>
{
    if (login.Username == "admin" && login.Password == "password")
    {
        var tokenHandler = new JwtSecurityTokenHandler();
        var tokenDescriptor = new SecurityTokenDescriptor
        {
            Subject = new ClaimsIdentity(new[] { new Claim(ClaimTypes.Name, login.Username) }),
            Expires = DateTime.UtcNow.AddHours(1),
            SigningCredentials = new SigningCredentials(new SymmetricSecurityKey(key), SecurityAlgorithms.HmacSha256Signature)
        };
        var token = tokenHandler.CreateToken(tokenDescriptor);
        return Results.Ok(new { token = tokenHandler.WriteToken(token) });
    }
    return Results.Unauthorized();
});

var companies = new List<Company>();

// CRUD Endpoints
app.MapPost("/companies", [Authorize] ([FromBody] Company company) =>
{
    if (companies.Any(c => c.CompanyCode == company.CompanyCode))
        return Results.BadRequest("Company with this code already exists.");

    companies.Add(company);
    return Results.Created($"/companies/{company.CompanyCode}", company);
});

app.MapGet("/companies", [Authorize] () => Results.Ok(companies));

app.MapGet("/companies/{companyCode}", [Authorize] (string companyCode) =>
{
    var company = companies.FirstOrDefault(c => c.CompanyCode == companyCode);
    return company is not null ? Results.Ok(company) : Results.NotFound();
});

app.MapPut("/companies/{companyCode}", [Authorize] (string companyCode, [FromBody] Company updatedCompany) =>
{
    var company = companies.FirstOrDefault(c => c.CompanyCode == companyCode);
    if (company is null) return Results.NotFound();

    company.CompanyName = updatedCompany.CompanyName;
    company.CompanyAddress = updatedCompany.CompanyAddress;
    company.CompanyGSTN = updatedCompany.CompanyGSTN;
    company.CompanyUserId = updatedCompany.CompanyUserId;
    company.CompanyStatus = updatedCompany.CompanyStatus;
    company.CompanyStartDate = updatedCompany.CompanyStartDate;
    company.CompanyNatureOfWork = updatedCompany.CompanyNatureOfWork;

    return Results.Ok(company);
});

app.MapDelete("/companies/{companyCode}", [Authorize] (string companyCode) =>
{
    var company = companies.FirstOrDefault(c => c.CompanyCode == companyCode);
    if (company is null) return Results.NotFound();

    companies.Remove(company);
    return Results.NoContent();
});

app.UseAuthentication();
app.UseAuthorization();
app.Run();
