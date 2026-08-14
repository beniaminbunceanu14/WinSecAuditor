using System.Threading.Tasks;
using WinSecAuditor.Services;

namespace WinSecAuditor.Remediation
{
    public class FirewallRemediator
    {
        private readonly IPowerShellEngine _psEngine;

        public FirewallRemediator(IPowerShellEngine psEngine)
        {
            _psEngine = psEngine;
        }

        public async Task<bool> BlockPortAsync(int port, string ruleName)
        {
            string script = $@"
                try {{
                    New-NetFirewallRule -DisplayName '{ruleName}' -Direction Inbound -LocalPort {port} -Protocol TCP -Action Block -ErrorAction Stop | Out-Null
                    Write-Output 'SUCCESS'
                }} catch {{
                    Write-Output 'ERROR'
                }}
            ";

            var result = await _psEngine.ExecuteAsync(script);

            // Verificăm dacă PowerShell a returnat SUCCESS, semn că regula a fost creată
            return result.Output.Contains("SUCCESS");
        }
    }
}