using System;
using System.Collections.Generic;
using System.Threading;
using System.Threading.Tasks;
using WinSecAuditor.Core;
using WinSecAuditor.Services;

namespace WinSecAuditor.Auditing
{
    public class PowerShellExecutionPolicyAuditor : ISecurityAuditor
    {
        private readonly IPowerShellEngine _psEngine;
        public string AuditorName => "PowerShell Execution Policy Auditor";

        public PowerShellExecutionPolicyAuditor(IPowerShellEngine psEngine)
        {
            _psEngine = psEngine;
        }

        public async Task<List<SecurityFinding>> RunAuditAsync(CancellationToken cancellationToken = default)
        {
            var findings = new List<SecurityFinding>();

            string script = @"
        try {
            $localMachine = Get-ExecutionPolicy -Scope LocalMachine
            $currentUser = Get-ExecutionPolicy -Scope CurrentUser
            $machinePolicy = Get-ExecutionPolicy -Scope MachinePolicy
            $userPolicy = Get-ExecutionPolicy -Scope UserPolicy

            Write-Output ('LocalMachine=' + $localMachine)
            Write-Output ('CurrentUser=' + $currentUser)
            Write-Output ('MachinePolicy=' + $machinePolicy)
            Write-Output ('UserPolicy=' + $userPolicy)
        } catch {
            Write-Output 'Error=QueryFailed'
        }
    ";

            var result = await _psEngine.ExecuteAsync(script, cancellationToken);

            string localMachine = "Unknown";
            string currentUser = "Unknown";
            string machinePolicy = "Unknown";
            string userPolicy = "Unknown";

            if (result.IsSuccess)
            {
                var lines = result.Output.Split(new[] { '\n', '\r' }, StringSplitOptions.RemoveEmptyEntries);
                foreach (var line in lines)
                {
                    var parts = line.Trim().Split('=');
                    if (parts.Length == 2)
                    {
                        switch (parts[0])
                        {
                            case "LocalMachine": localMachine = parts[1]; break;
                            case "CurrentUser": currentUser = parts[1]; break;
                            case "MachinePolicy": machinePolicy = parts[1]; break;
                            case "UserPolicy": userPolicy = parts[1]; break;
                        }
                    }
                }
            }

            // Calculăm efectivă IGNORÂND scope-ul Process (volatil, nu reflectă postura durabilă).
            // Ordinea de precedență Microsoft: MachinePolicy → UserPolicy → CurrentUser → LocalMachine
            // Prima valoare != Undefined câștigă.
            string effectivePersistent = FirstDefined(machinePolicy, userPolicy, currentUser, localMachine) ?? "Undefined";
            string culprit = FindCulprit(machinePolicy, userPolicy, currentUser, localMachine);

            bool isInsecure = effectivePersistent.Equals("Unrestricted", StringComparison.OrdinalIgnoreCase) ||
                              effectivePersistent.Equals("Bypass", StringComparison.OrdinalIgnoreCase);

            bool gpoControlled = !machinePolicy.Equals("Undefined", StringComparison.OrdinalIgnoreCase) ||
                                 !userPolicy.Equals("Undefined", StringComparison.OrdinalIgnoreCase);

            string description;
            if (!isInsecure)
            {
                description = effectivePersistent.Equals("Undefined", StringComparison.OrdinalIgnoreCase)
                    ? "PowerShell Execution Policy nu este configurat explicit pe niciun scope persistent — sistemul folosește default-ul Windows (Restricted pentru client, RemoteSigned pentru server)."
                    : $"PowerShell Execution Policy persistent este '{effectivePersistent}' (setat la scope '{culprit}') — o valoare sigură care restricționează execuția de scripturi neverificate.";
            }
            else
            {
                description = $"PowerShell rulează cu politica persistentă '{effectivePersistent}' (setată la scope '{culprit}'), care permite execuția scripturilor nesemnate, inclusiv a celor descărcate de pe internet. Vector major pentru fileless malware și mișcare laterală prin PowerShell.";
            }

            string recommendation;
            if (!isInsecure)
            {
                recommendation = string.Empty;
            }
            else if (culprit == "MachinePolicy" || culprit == "UserPolicy")
            {
                recommendation = "Politica insecură este aplicată prin Group Policy. Contactează administratorul de domeniu pentru modificarea GPO-ului corespunzător.";
            }
            else
            {
                recommendation = "Setează Execution Policy la 'RemoteSigned' (permite scripturi locale, blochează cele remote nesemnate) sau 'AllSigned' (necesită semnătură digitală pentru orice script).";
            }

            findings.Add(new SecurityFinding
            {
                Id = "SYS-004",
                Category = SecurityCategory.WindowsSecurity,
                Title = "PowerShell Execution Policy",
                Description = description,
                Evidence = $"LocalMachine: {localMachine} | CurrentUser: {currentUser} | MachinePolicy: {machinePolicy} | UserPolicy: {userPolicy} (Process scope ignored)",
                Status = isInsecure ? FindingStatus.Fail : FindingStatus.Pass,
                Severity = Severity.High,
                Recommendation = recommendation,
                CanRemediate = isInsecure && !gpoControlled,
                PenaltyPoints = 15
            });

            return findings;
        }

        /// <summary>Returnează prima valoare care nu e 'Undefined', în ordinea de precedență Windows.</summary>
        private static string? FirstDefined(params string[] scopes)
        {
            foreach (var s in scopes)
            {
                if (!string.IsNullOrEmpty(s) && !s.Equals("Undefined", StringComparison.OrdinalIgnoreCase))
                    return s;
            }
            return null;
        }

        /// <summary>Găsește numele scope-ului care dictează politica efectivă persistentă.</summary>
        private static string FindCulprit(string machinePolicy, string userPolicy, string currentUser, string localMachine)
        {
            if (!machinePolicy.Equals("Undefined", StringComparison.OrdinalIgnoreCase)) return "MachinePolicy";
            if (!userPolicy.Equals("Undefined", StringComparison.OrdinalIgnoreCase)) return "UserPolicy";
            if (!currentUser.Equals("Undefined", StringComparison.OrdinalIgnoreCase)) return "CurrentUser";
            if (!localMachine.Equals("Undefined", StringComparison.OrdinalIgnoreCase)) return "LocalMachine";
            return "Default (Windows)";
        }
    }
}