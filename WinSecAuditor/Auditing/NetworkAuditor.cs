using System;
using System.Collections.Generic;
using System.Threading;
using System.Threading.Tasks;
using WinSecAuditor.Core;
using WinSecAuditor.Services;

namespace WinSecAuditor.Auditing
{
    public class NetworkAuditor : ISecurityAuditor
    {
        private readonly IPowerShellEngine _psEngine;
        public string AuditorName => "Network Exposure Auditor";

        public NetworkAuditor(IPowerShellEngine psEngine)
        {
            _psEngine = psEngine;
        }

        public async Task<List<SecurityFinding>> RunAuditAsync(CancellationToken cancellationToken = default)
        {
            var findings = new List<SecurityFinding>();

            // Verificăm portul și dacă există o regulă de firewall activă care blochează portul 445 Inbound
            string script = @"
                $portListening = $false
                $conn = Get-NetTCPConnection -State Listen -LocalPort 445 -ErrorAction SilentlyContinue
                if ($conn) { $portListening = $true }

                $firewallBlocked = $false
                $rules = Get-NetFirewallRule -Direction Inbound -Action Block -Enabled True -ErrorAction SilentlyContinue | Get-NetFirewallPortFilter -ErrorAction SilentlyContinue
                foreach ($rule in $rules) {
                    if ($rule.LocalPort -eq 445) {
                        $firewallBlocked = $true
                    }
                }

                Write-Output ('Listening=' + $portListening)
                Write-Output ('FirewallBlocked=' + $firewallBlocked)
            ";

            var result = await _psEngine.ExecuteAsync(script, cancellationToken);

            bool isListening = false;
            bool isFirewallBlocked = false;

            if (result.IsSuccess && !string.IsNullOrWhiteSpace(result.Output))
            {
                var lines = result.Output.Split(new[] { '\n', '\r' }, StringSplitOptions.RemoveEmptyEntries);
                foreach (var line in lines)
                {
                    var parts = line.Trim().Split('=');
                    if (parts.Length == 2)
                    {
                        if (parts[0] == "Listening") isListening = bool.Parse(parts[1]);
                        if (parts[0] == "FirewallBlocked") isFirewallBlocked = bool.Parse(parts[1]);
                    }
                }
            }

            // O vulnerabilitate de rețea este considerată pasată dacă portul este închis SAU este blocat explicit de Firewall
            bool smbSecure = !isListening || isFirewallBlocked;

            findings.Add(new SecurityFinding
            {
                Id = "NET-001",
                Category = SecurityCategory.Network,
                Title = "SMB Exposure (Port 445)",
                Description = smbSecure
                    ? "Portul 445 (SMB) este securizat prin reguli de Firewall sau este închis."
                    : "Portul 445 (SMB) acceptă conexiuni de intrare nefiltrate.",
                Evidence = $"Listening: {isListening}, Firewall Blocked Rule Active: {isFirewallBlocked}",
                Status = smbSecure ? FindingStatus.Pass : FindingStatus.Fail,
                Severity = Severity.High,
                Recommendation = smbSecure ? string.Empty : "Blochează traficul Inbound pe portul 445 din Windows Firewall.",
                RemediationId = "BLOCK-SMB-445",
                CanRemediate = !smbSecure,
                PenaltyPoints = 15
            });

            // Verificăm RDP (3389)
            string rdpScript = @"
                $rdpListening = $false
                $conn = Get-NetTCPConnection -State Listen -LocalPort 3389 -ErrorAction SilentlyContinue
                if ($conn) { $rdpListening = $true }
                Write-Output ('RDPListening=' + $rdpListening)
            ";

            var rdpResult = await _psEngine.ExecuteAsync(rdpScript, cancellationToken);
            bool rdpListening = false;
            if (rdpResult.IsSuccess && rdpResult.Output.Contains("RDPListening=True"))
            {
                rdpListening = true;
            }

            findings.Add(new SecurityFinding
            {
                Id = "NET-002",
                Category = SecurityCategory.Network,
                Title = "RDP Exposure (Port 3389)",
                Description = rdpListening
                    ? "Portul 3389 (Remote Desktop) este deschis pe rețea."
                    : "Portul 3389 (RDP) nu expune sistemul.",
                Evidence = $"RDP Port 3389 Listening: {rdpListening}",
                Status = rdpListening ? FindingStatus.Warning : FindingStatus.Pass,
                Severity = Severity.Medium,
                Recommendation = rdpListening ? "Dacă nu folosești RDP, dezactivează serviciul sau restrânge accesul." : string.Empty,
                CanRemediate = rdpListening,
                PenaltyPoints = 10
            });

            return findings;
        }
    }
}