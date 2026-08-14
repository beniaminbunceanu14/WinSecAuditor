using System.Collections.Generic;
using System.Threading;
using System.Threading.Tasks;
using WinSecAuditor.Core;
using WinSecAuditor.Services;

namespace WinSecAuditor.Auditing
{
    public class SecureBootAuditor : ISecurityAuditor
    {
        private readonly IPowerShellEngine _psEngine;
        public string AuditorName => "Secure Boot Auditor";

        public SecureBootAuditor(IPowerShellEngine psEngine)
        {
            _psEngine = psEngine;
        }

        public async Task<List<SecurityFinding>> RunAuditAsync(CancellationToken cancellationToken = default)
        {
            var findings = new List<SecurityFinding>();

            // Verificăm starea Secure Boot prin cmdlet-ul nativ UEFI
            string script = @"
                try {
                    $sb = Confirm-SecureBootUEFI -ErrorAction Stop
                    Write-Output ('SecureBootEnabled=' + $sb)
                } catch {
                    Write-Output 'SecureBootEnabled=NotSupportedOrError'
                }
            ";

            var result = await _psEngine.ExecuteAsync(script, cancellationToken);

            bool isSecureBootEnabled = false;
            bool isSupported = true;

            if (result.IsSuccess)
            {
                if (result.Output.Contains("SecureBootEnabled=True"))
                {
                    isSecureBootEnabled = true;
                }
                else if (result.Output.Contains("NotSupportedOrError"))
                {
                    isSupported = false;
                }
            }

            findings.Add(new SecurityFinding
            {
                Id = "SYS-002",
                Category = SecurityCategory.SystemConfiguration,
                Title = "UEFI Secure Boot Status",
                Description = isSecureBootEnabled
                    ? "Secure Boot este activat, protejând sistemul de bootkits și malware la nivel de firmware."
                    : (isSupported ? "Secure Boot este dezactivat, lăsând sistemul vulnerabil la amenințări persistente la nivel de boot." : "Secure Boot nu este suportat de această platformă (mod Legacy BIOS)."),
                Evidence = $"Firmware Result: {result.Output.Trim()}",
                Status = isSecureBootEnabled ? FindingStatus.Pass : FindingStatus.Fail,
                Severity = Severity.High,
                Recommendation = isSecureBootEnabled ? string.Empty : "Activează Secure Boot din setările firmware UEFI/BIOS ale plăcii de bază.",
                CanRemediate = false,
                PenaltyPoints = 15
            });

            return findings;
        }
    }
}