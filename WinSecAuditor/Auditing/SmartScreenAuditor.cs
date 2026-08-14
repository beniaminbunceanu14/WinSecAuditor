using System.Collections.Generic;
using System.Threading;
using System.Threading.Tasks;
using WinSecAuditor.Core;
using WinSecAuditor.Services;

namespace WinSecAuditor.Auditing
{
    public class SmartScreenAuditor : ISecurityAuditor
    {
        private readonly IPowerShellEngine _psEngine;
        public string AuditorName => "Windows Defender SmartScreen Auditor";

        public SmartScreenAuditor(IPowerShellEngine psEngine)
        {
            _psEngine = psEngine;
        }

        public async Task<List<SecurityFinding>> RunAuditAsync(CancellationToken cancellationToken = default)
        {
            var findings = new List<SecurityFinding>();

            // Verificăm starea SmartScreen din Registry pentru Explorer/Shell
            string script = @"
                try {
                    $path = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer'
                    $smartScreen = (Get-ItemProperty -Path $path -Name 'SmartScreenEnabled' -ErrorAction Stop).SmartScreenEnabled
                    Write-Output ('SmartScreenEnabled=' + $smartScreen)
                } catch {
                    Write-Output 'SmartScreenEnabled=Unknown'
                }
            ";

            var result = await _psEngine.ExecuteAsync(script, cancellationToken);

            bool isSmartScreenActive = false;
            string rawValue = "Unknown";

            if (result.IsSuccess)
            {
                foreach (var line in result.Output.Split(new[] { '\n', '\r' }, System.StringSplitOptions.RemoveEmptyEntries))
                {
                    var parts = line.Trim().Split('=');
                    if (parts.Length == 2 && parts[0] == "SmartScreenEnabled")
                    {
                        rawValue = parts[1];
                        if (rawValue.Equals("RequireAdmin", System.StringComparison.OrdinalIgnoreCase) ||
                            rawValue.Equals("On", System.StringComparison.OrdinalIgnoreCase))
                        {
                            isSmartScreenActive = true;
                        }
                    }
                }
            }

            findings.Add(new SecurityFinding
            {
                Id = "SYS-003",
                Category = SecurityCategory.WindowsSecurity,
                Title = "Windows Defender SmartScreen",
                Description = isSmartScreenActive
                    ? "SmartScreen este activat și verifică fișierele și aplicațiile descărcate."
                    : "SmartScreen este dezactivat, crescând riscul de execuție a aplicațiilor malițioase netestate.",
                Evidence = $"SmartScreenEnabled Registry Value: {rawValue}",
                Status = isSmartScreenActive ? FindingStatus.Pass : FindingStatus.Fail,
                Severity = Severity.Medium,
                Recommendation = isSmartScreenActive ? string.Empty : "Activează SmartScreen din setările Windows Security (App & browser control).",
                CanRemediate = !isSmartScreenActive,
                PenaltyPoints = 10
            });

            return findings;
        }
    }
}