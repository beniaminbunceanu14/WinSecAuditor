using System;
using System.Collections.Generic;
using System.Threading;
using System.Threading.Tasks;
using WinSecAuditor.Core;
using WinSecAuditor.Services;

namespace WinSecAuditor.Auditing
{
    public class BitLockerAuditor : ISecurityAuditor
    {
        private readonly IPowerShellEngine _psEngine;
        public string AuditorName => "BitLocker Encryption Auditor";

        public BitLockerAuditor(IPowerShellEngine psEngine)
        {
            _psEngine = psEngine;
        }

        public async Task<List<SecurityFinding>> RunAuditAsync(CancellationToken cancellationToken = default)
        {
            var findings = new List<SecurityFinding>();

            // Interogăm starea BitLocker pentru unitatea de sistem (C:)
            string script = @"
                try {
                    $vol = Get-BitLockerVolume -MountPoint 'C:' -ErrorAction Stop
                    Write-Output ('VolumeStatus=' + $vol.VolumeStatus)
                    Write-Output ('ProtectionStatus=' + $vol.ProtectionStatus)
                    Write-Output ('EncryptionMethod=' + $vol.EncryptionMethod)
                } catch {
                    Write-Output 'Error=AccessDeniedOrNotSupported'
                }
            ";

            var result = await _psEngine.ExecuteAsync(script, cancellationToken);

            string volumeStatus = "Unknown";
            string protectionStatus = "Unknown";
            string encryptionMethod = "None";
            bool isEncrypted = false;

            if (result.IsSuccess)
            {
                var lines = result.Output.Split(new[] { '\n', '\r' }, StringSplitOptions.RemoveEmptyEntries);
                foreach (var line in lines)
                {
                    var parts = line.Trim().Split('=');
                    if (parts.Length == 2)
                    {
                        if (parts[0] == "VolumeStatus") volumeStatus = parts[1];
                        if (parts[0] == "ProtectionStatus") protectionStatus = parts[1];
                        if (parts[0] == "EncryptionMethod") encryptionMethod = parts[1];
                    }
                }

                // Considerăm discul criptat și protejat dacă starea este FullyEncrypted sau On
                if (protectionStatus.Equals("On", StringComparison.OrdinalIgnoreCase) ||
                    volumeStatus.Equals("FullyEncrypted", StringComparison.OrdinalIgnoreCase))
                {
                    isEncrypted = true;
                }
            }

            var evidence = new SecurityEvidence
            {
                RawData = result.Output,
                KeyValues = new Dictionary<string, string>
                {
                    { "Drive", "C:" },
                    { "VolumeStatus", volumeStatus },
                    { "ProtectionStatus", protectionStatus },
                    { "EncryptionMethod", encryptionMethod }
                },
                IsCollectedSuccessfully = result.IsSuccess
            };

            findings.Add(new SecurityFinding
            {
                Id = "ENC-001",
                Category = SecurityCategory.Encryption,
                Title = "OS Volume Encryption (BitLocker)",
                Description = isEncrypted
                    ? "Unitatea sistemului (C:) este criptată și protejată prin BitLocker."
                    : "Unitatea sistemului (C:) nu este criptată, expunând datele în caz de furt sau acces fizic.",
                Evidence = $"Drive: C: | Protection: {protectionStatus} | Method: {encryptionMethod}",
                Status = isEncrypted ? FindingStatus.Pass : FindingStatus.Fail,
                Severity = Severity.High,
                Recommendation = isEncrypted ? string.Empty : "Activează BitLocker pe unitatea sistemului din panoul de control sau prin PowerShell (Enable-BitLocker).",
                CanRemediate = false, // Lăsăm pe ghidat/manual momentan pentru siguranța datelor
                PenaltyPoints = 15
            });

            return findings;
        }
    }
}