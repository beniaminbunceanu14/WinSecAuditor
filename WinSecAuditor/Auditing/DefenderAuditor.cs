using System;
using System.Collections.Generic;
using System.Threading;
using System.Threading.Tasks;
using WinSecAuditor.Core;
using WinSecAuditor.Services;

namespace WinSecAuditor.Auditing
{
    public class DefenderAuditor : ISecurityAuditor
    {
        private readonly IPowerShellEngine _psEngine;

        public string AuditorName => "Windows Defender Auditor";

        public DefenderAuditor(IPowerShellEngine psEngine)
        {
            _psEngine = psEngine;
        }

        public async Task<List<SecurityFinding>> RunAuditAsync(CancellationToken cancellationToken = default)
        {
            var findings = new List<SecurityFinding>();

            string script = @"
                $status = Get-MpComputerStatus
                Write-Output ('AMServiceEnabled=' + $status.AMServiceEnabled)
                Write-Output ('RealTimeProtectionEnabled=' + $status.RealTimeProtectionEnabled)
                Write-Output ('AntispywareEnabled=' + $status.AntispywareEnabled)
            ";

            var result = await _psEngine.ExecuteAsync(script, cancellationToken);

            bool amService = false, realTime = false, antiSpyware = false;

            if (result.IsSuccess)
            {
                var lines = result.Output.Split(new[] { '\n', '\r' }, StringSplitOptions.RemoveEmptyEntries);
                foreach (var line in lines)
                {
                    var parts = line.Trim().Split('=');
                    if (parts.Length == 2)
                    {
                        bool isTrue = parts[1].Equals("True", StringComparison.OrdinalIgnoreCase);
                        if (parts[0] == "AMServiceEnabled") amService = isTrue;
                        if (parts[0] == "RealTimeProtectionEnabled") realTime = isTrue;
                        if (parts[0] == "AntispywareEnabled") antiSpyware = isTrue;
                    }
                }
            }
            else
            {
                findings.Add(new SecurityFinding
                {
                    Id = "DEF-ERR",
                    Category = SecurityCategory.WindowsSecurity,
                    Title = "Defender Status Error",
                    Description = "Nu s-a putut extrage telemetria din nucleul Windows Defender.",
                    Evidence = result.Error,
                    Status = FindingStatus.Error,
                    Severity = Severity.High,
                    Recommendation = "Verifică dacă serviciul Windows Defender rulează și dacă ai permisiuni suficiente.",
                    PenaltyPoints = 15
                });
                return findings;
            }

            findings.Add(new SecurityFinding
            {
                Id = "DEF-001",
                Category = SecurityCategory.WindowsSecurity,
                Title = "AntiMalware Service",
                Description = "Verifică dacă serviciul de bază Windows Defender AntiMalware (MsMpEng.exe) rulează.",
                Evidence = $"AMServiceEnabled = {amService}",
                Status = amService ? FindingStatus.Pass : FindingStatus.Fail,
                Severity = Severity.Critical,
                Recommendation = amService ? string.Empty : "Pornește serviciul Windows Defender din consolă sau services.msc.",
                CanRemediate = !amService,
                PenaltyPoints = 20
            });

            findings.Add(new SecurityFinding
            {
                Id = "DEF-002",
                Category = SecurityCategory.WindowsSecurity,
                Title = "Real-Time Protection",
                Description = "Verifică dacă modulul de protecție în timp real interceptează și scanează fișierele accesate.",
                Evidence = $"RealTimeProtectionEnabled = {realTime}",
                Status = realTime ? FindingStatus.Pass : FindingStatus.Fail,
                Severity = Severity.Critical,
                Recommendation = realTime ? string.Empty : "Activează Real-Time Protection din setările Windows Security.",
                CanRemediate = !realTime,
                PenaltyPoints = 20
            });

            findings.Add(new SecurityFinding
            {
                Id = "DEF-003",
                Category = SecurityCategory.WindowsSecurity,
                Title = "AntiSpyware Module",
                Description = "Verifică dacă modulul care blochează aplicațiile de spionaj este activ.",
                Evidence = $"AntispywareEnabled = {antiSpyware}",
                Status = antiSpyware ? FindingStatus.Pass : FindingStatus.Fail,
                Severity = Severity.High,
                Recommendation = antiSpyware ? string.Empty : "Activează definițiile și modulul AntiSpyware.",
                CanRemediate = !antiSpyware,
                PenaltyPoints = 10
            });

            return findings;
        }
    }
}