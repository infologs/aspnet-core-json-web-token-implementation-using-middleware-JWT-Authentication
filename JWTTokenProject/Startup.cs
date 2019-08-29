using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using JWTTokenProject.Controllers;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Tokens;

namespace JWTTokenProject
{
    public class Startup
    {
        private static readonly string secretKey = "mysupersecret_secretkey!123";

        public Startup(IConfiguration configuration)
        {
            Configuration = configuration;
        }

        public IConfiguration Configuration { get; }

        // This method gets called by the runtime. Use this method to add services to the container.
        public void ConfigureServices(IServiceCollection services)
        {
            var secretKey = "mysupersecret_secretkey!123";
            var signingKey = new SymmetricSecurityKey(Encoding.ASCII.GetBytes(secretKey));


            var tokenValidationParameters = new TokenValidationParameters
            {
                // The signing key must match!
                ValidateIssuerSigningKey = true,
                IssuerSigningKey = signingKey,

                // Validate the JWT Issuer (iss) claim
                ValidateIssuer = true,
                ValidIssuer = "infologs.in",

                // Validate the JWT Audience (aud) claim
                ValidateAudience = true,
                ValidAudience = "Process Runner Family",

                // Validate the token expiry
                ValidateLifetime = true,                

                // If you want to allow a certain amount of clock drift, set that here:
                ClockSkew = TimeSpan.Zero,

            };

            services.AddAuthentication().AddJwtBearer(options => {
                options.Audience = "Process Runner Family";
                options.ClaimsIssuer = "infologs.in";
                options.TokenValidationParameters = tokenValidationParameters;
            });
            services.AddMvc().SetCompatibilityVersion(CompatibilityVersion.Version_2_2);
        }

        // This method gets called by the runtime. Use this method to configure the HTTP request pipeline.
        public void Configure(IApplicationBuilder app, IHostingEnvironment env)
        {
            if (env.IsDevelopment())
            {
                app.UseDeveloperExceptionPage();
            }

            // Add JWT generation endpoint:

            var signingKey = new SymmetricSecurityKey(Encoding.ASCII.GetBytes(secretKey));
            var options = new TokenProviderOptions
            {
                Audience = "Process Runner Family",
                Issuer = "infologs.in",
                SigningCredentials = new SigningCredentials(signingKey, SecurityAlgorithms.HmacSha512),                
            };

            
            app.UseMiddleware<TokenProviderMiddleware>(Options.Create(options));

            app.UseMvc();
        }
    }
}
