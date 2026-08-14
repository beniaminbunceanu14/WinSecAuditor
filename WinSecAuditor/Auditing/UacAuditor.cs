using System;
using System.Collections.Generic;
using System.Threading;
using System.Threading.Tasks;
using WinSecAuditor.Core;
using WinSecAuditor.Services;

namespace WinSecAuditor.Auditing
{
    public class UacAuditor : ISecurityAuditor
    {
        private readonly IPowerShellEngine _psEngine;
        public string AuditorName => "User Account Control (UAC) Auditor";

        public UacAuditor(IPowerShellEngine psEngine)
        {
            _psEngine = psEngine;
        }

        public async Task<List<SecurityFinding>> RunAuditAsync(CancellationToken cancellationToken = default)
        {
            var findings = new List<SecurityFinding>();

            // Citim starea UAC din Registry
            string script = @"
                try {
                    $path = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System'
                    $enableLua = (Get-ItemProperty -Path $path -Name 'EnableLUA' -ErrorAction Stop).EnableLUA
                    $consent = (Get-ItemProperty -Path $path -Name 'ConsentPromptBehaviorAdmin' -ErrorAction Stop).ConsentPromptBehaviorAdmin
                    
                    Write-Output ('EnableLUA=' + $enableLua)
                    Write-Output ('ConsentPromptBehaviorAdmin=' + $consent)
                } catch {
                    Write-Output 'Error=RegistryReadFailed'
                }
            ";

            var result = await _psEngine.ExecuteAsync(script, cancellationToken);

            int enableLua = -1;
            int consentBehavior = -1;
            bool isUacEnabled = false;

            if (result.IsSuccess)
            {
                var lines = result.Output.Split(new[] { '\n', '\r' }, StringSplitOptions.RemoveEmptyEntries);
                foreach (var line in lines)
                {
                    var parts = line.Trim().Split('=');
                    if (parts.Length == 2)
                    {
                        if (parts[0] == "EnableLUA") int.TryParse(parts[1], out enableLua);
                        if (parts[0] == "ConsentPromptBehaviorAdmin") int.TryParse(parts[1], out consentBehavior);
                    }
                }

                // UAC este considerat activ dacă EnableLUA este 1
                if (enableLua == 1)
                {
                    isUacEnabled = true;
                }
            }

            findings.Add(new SecurityFinding
            {
                Id = "SYS-001",
                Category = SecurityCategory.WindowsSecurity,
                Title = "User Account Control (UAC) Status",
                Description = isUacEnabled
                    ? "Controlul Contului de Utilizator (UAC) este activat pe sistem."
                    : "UAC este dezactivat, permițând aplicațiilor să ruleze cu drepturi maxime de administrator fără notificare.",
                Evidence = $"EnableLUA: {enableLua}, ConsentPromptBehaviorAdmin: {consentBehavior}",
                Status = isUacEnabled ? FindingStatus.Pass : FindingStatus.Fail,
                Severity = Severity.Critical,
                Recommendation = isUacEnabled ? string.Empty : "Activează UAC din panoul de control (User Account Control Settings) sau prin setările de securitate.",
                CanRemediate = !isUacEnabled,
                PenaltyPoints = 20
            });

            return findings;
        }
    }
}