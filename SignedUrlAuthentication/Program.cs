using SignedUrlAuthentication.Authentication;
using SignedUrlAuthentication.Services;
var builder = WebApplication.CreateBuilder(args);

// Add services to the container.
builder.Services.AddSingleton<ISignedUrlService, SignedUrlService>();
builder.Services.AddControllers();
// Learn more about configuring Swagger/OpenAPI at https://aka.ms/aspnetcore/swashbuckle
builder.Services.AddEndpointsApiExplorer();
builder.Services.AddSwaggerGen();

builder.Services.AddAuthentication()
    .AddScheme<SignedUrlAuthSchemeOptions, SignedUrlAuthHandler>("Signed Url", options => {});

builder.Services.Configure<SignedUrlOptions>(o => builder.Configuration.GetSection(SignedUrlOptions.SignedUrlOptionsKey).Bind(o));

var app = builder.Build();

// Configure the HTTP request pipeline.
if (app.Environment.IsDevelopment()) {
    app.UseSwagger();
    app.UseSwaggerUI();
}

app.UseHttpsRedirection();

app.UseAuthentication();
app.UseAuthorization();

app.MapControllers();

app.Run();
