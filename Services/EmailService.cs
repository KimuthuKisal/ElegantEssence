
using Microsoft.Identity.Client.Platforms.Features.DesktopOs.Kerberos;
using Microsoft.IdentityModel.Protocols;
using System.Net;
using System.Net.Mail;

namespace ElegantEssence.Services
{
    public class EmailService : IEmailService
    {
        private readonly IConfiguration _configuration;

        public EmailService(IConfiguration configuration)
        {
            _configuration = configuration;
        }

        public async Task SendEmailAsync(string toEmail, string subject, string body)
        {
            var fromEmail = _configuration["EmailSettings:From"];
            var smtpServer = _configuration["EmailSettings:SmtpServer"];
            var port = int.Parse(_configuration["EmailSettings:Port"]!);
            var userName = _configuration["EmailSettings:Username"];
            var password = _configuration["EmailSettings:Password"];
            
            var message = new MailMessage(fromEmail!, toEmail, subject, body);
            message.IsBodyHtml = true;

            using var client = new SmtpClient(smtpServer, port)
            {
                Credentials = new NetworkCredential(userName, password),
                EnableSsl = true
            };

            await client.SendMailAsync(message);
        }
    }
}
