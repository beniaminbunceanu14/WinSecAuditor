using System;
using System.Collections.Generic;
using System.Threading;
using System.Threading.Tasks;
using WinSecAuditor.Core;
using WinSecAuditor.Services;

namespace WinSecAuditor.Auditing
{
    public class StartupAuditor : ISecurityAuditor
    {
        private readonly IPowerShellEngine _psEngine;
        public string AuditorName => "Startup & Persistence Auditor";

        public StartupAuditor(IPowerShellEngine psEngine)
        {
            _psEngine = psEngine;
        }

        public async Task<List<SecurityFinding>> RunAuditAsync(CancellationToken cancellationToken = default)
        {
            var findings = new List<SecurityFinding>();

            string script = @"
                $startupKeys = @('HKCU:\Software\Microsoft\Windows\CurrentVersion\Run', 'HKLM:\Software\Microsoft\Windows\CurrentVersion\Run')
                $whitelistPattern = '(?i)opera\.exe|discord\\update\.exe'
                
                foreach ($key in $startupKeys) {
                    $entries = Get-ItemProperty $key -ErrorAction SilentlyContinue
                    $entries.psobject.properties | Where-Object { 
                        ($_.Value -match '\\AppData\\' -or $_.Value -match '\\Temp\\') -and ($_.Value -notmatch $whitelistPattern) 
                    } | ForEach-Object {
                        Write-Output ($_.Name + '|' + $_.Value)
                    }
                }
            ";

            var result = await _psEngine.ExecuteAsync(script, cancellationToken);

            if (result.IsSuccess && !string.IsNullOrWhiteSpace(result.Output))
            {
                var lines = result.Output.Split(new[] { '\n', '\r' }, StringSplitOptions.RemoveEmptyEntries);
                foreach (var line in lines)
                {
                    var parts = line.Split('|');
                    if (parts.Length >= 2)
                    {
                        findings.Add(new SecurityFinding
                        {
                            Id = "STR-001",
                            Category = SecurityCategory.Startup,
                            Title = $"Untrusted Startup Entry: {parts[0]}",
                            Description = "Programul rulează automat dintr-o locație neobișnuită (AppData/Temp).",
                            Evidence = $"Registry Path value: {parts[1]}",
                            Status = FindingStatus.Warning,
                            Severity = Severity.High,
                            Recommendation = "Verifică dacă acest program este legitim.",
                            CanRemediate = false,
                            PenaltyPoints = 10
                        });
                    }
                }
            }

            if (findings.Count == 0)
            {
                findings.Add(new SecurityFinding
                {
                    Id = "STR-OK",
                    Category = SecurityCategory.Startup,
                    Title = "Startup Integrity",
                    Description = "Nu au fost detectate aplicații neobișnuite care pornesc automat din locații vulnerabile.",
                    Evidence = "Startup registry keys clean.",
                    Status = FindingStatus.Pass,
                    Severity = Severity.Info,
                    Recommendation = string.Empty,
                    CanRemediate = false,
                    PenaltyPoints = 0
                });
            }

            return findings;
        }
    }
}