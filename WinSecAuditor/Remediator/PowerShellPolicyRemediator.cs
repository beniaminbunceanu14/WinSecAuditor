using System.Threading.Tasks;
using WinSecAuditor.Services;

namespace WinSecAuditor.Remediation
{
    /// <summary>
    /// Setează PowerShell Execution Policy la RemoteSigned pe LocalMachine și CurrentUser,
    /// și curăță scope-ul Process. Nu poate suprascrie MachinePolicy/UserPolicy (GPO managed).
    /// </summary>
    public class PowerShellPolicyRemediator
    {
        private readonly IPowerShellEngine _psEngine;

        public PowerShellPolicyRemediator(IPowerShellEngine psEngine)
        {
            _psEngine = psEngine;
        }

        public async Task<bool> SetSecurePolicyAsync()
        {
            string script = @"
                $ErrorActionPreference = 'Continue'
                $ok = $true

                # Scope 1: LocalMachine — via registry (cmdlet e blocat pe unele sisteme)
                try {
                    $regPath = 'HKLM:\SOFTWARE\Microsoft\PowerShell\1\ShellIds\Microsoft.PowerShell'
                    if (-not (Test-Path $regPath)) { New-Item -Path $regPath -Force | Out-Null }
                    Set-ItemProperty -Path $regPath -Name 'ExecutionPolicy' -Value 'RemoteSigned' -Type String -Force
                } catch { $ok = $false }

                # Scope 2: CurrentUser — via registry
                try {
                    $regPathUser = 'HKCU:\SOFTWARE\Microsoft\PowerShell\1\ShellIds\Microsoft.PowerShell'
                    if (-not (Test-Path $regPathUser)) { New-Item -Path $regPathUser -Force | Out-Null }
                    Set-ItemProperty -Path $regPathUser -Name 'ExecutionPolicy' -Value 'RemoteSigned' -Type String -Force
                } catch { $ok = $false }

                # Scope 3: încearcă și prin cmdlet ca dublă asigurare
                try {
                    Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope LocalMachine -Force -Confirm:$false -ErrorAction SilentlyContinue
                    Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope CurrentUser  -Force -Confirm:$false -ErrorAction SilentlyContinue
                } catch { }

                # Verificare pe scope-urile pe care le putem controla
                $lm = Get-ExecutionPolicy -Scope LocalMachine
                $cu = Get-ExecutionPolicy -Scope CurrentUser

                if ($lm -eq 'RemoteSigned' -or $lm -eq 'AllSigned' -or $lm -eq 'Restricted') {
                    if ($cu -eq 'RemoteSigned' -or $cu -eq 'AllSigned' -or $cu -eq 'Restricted' -or $cu -eq 'Undefined') {
                        Write-Output 'RESULT=SUCCESS'
                    } else {
                        Write-Output ('RESULT=CURRENTUSER_FAIL:' + $cu)
                    }
                } else {
                    Write-Output ('RESULT=LOCALMACHINE_FAIL:' + $lm)
                }
            ";

            var result = await _psEngine.ExecuteAsync(script);
            return result.IsSuccess && result.Output.Contains("RESULT=SUCCESS");
        }
    }
}