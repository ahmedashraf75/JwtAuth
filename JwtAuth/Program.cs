using JwtAuth.Data;
using JwtAuth.Services;
using Microsoft.EntityFrameworkCore;
using Scalar.AspNetCore;
using System.IdentityModel.Tokens.Jwt;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.IdentityModel.Tokens;
using System.Text;
using Microsoft.Extensions.DependencyInjection;

var builder = WebApplication.CreateBuilder(args);

// Add services to the container.

builder.Services.AddControllers();
// Learn more about configuring OpenAPI at https://aka.ms/aspnet/openapi
builder.Services.AddOpenApi();


//here is I am adding the service of Authentication 
builder.Services.AddAuthentication(JwtBearerDefaults.AuthenticationScheme)
                                     .AddJwtBearer(options =>
                                     {
                                         //Every thing inside TokenValidationParameter insure the strict rules that what makes Token valid  
                                         options.TokenValidationParameters = new TokenValidationParameters
                                         {
                                             ValidateIssuer = true,
                                             ValidIssuer = builder.Configuration["AppSettings:Issuer"],
                                             ValidateAudience = true,
                                             ValidAudience = builder.Configuration["AppSettings:Audience"],
                                             ValidateLifetime = true,
                                             ValidateIssuerSigningKey = true,
                                             IssuerSigningKey = new SymmetricSecurityKey(
                                                                                Encoding.UTF8.GetBytes(builder.Configuration["AppSettings:Token"]!))
                                         };
                                     });

builder.Services.AddDbContext<UserDbContext>(options =>
                options.UseSqlServer(builder.Configuration.GetConnectionString("UserDatabase")));

builder.Services.AddScoped<IAuthService, AuthService>();
var app = builder.Build();



// Configure the HTTP request pipeline.
// this block is to enable OpenAPI only in development environment
if (app.Environment.IsDevelopment())
{
    app.MapOpenApi();
    app.MapScalarApiReference();
}

app.UseHttpsRedirection();
app.UseAuthentication();
app.UseAuthorization();

app.MapControllers();

app.Run();
