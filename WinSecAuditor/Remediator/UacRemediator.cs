using System;
using System.Threading.Tasks;
using Microsoft.Win32;

namespace WinSecAuditor.Remediation
{
    /// <summary>
    /// Activează User Account Control prin scriere directă în registri.
    /// Necesită drepturi de Administrator. UAC devine complet activ după restart.
    /// </summary>
    public class UacRemediator
    {
        private const string PolicyKeyPath = @"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System";

        public Task<bool> EnableUacAsync()
        {
            return Task.Run(() =>
            {
                try
                {
                    using (RegistryKey? key = Registry.LocalMachine.OpenSubKey(PolicyKeyPath, writable: true))
                    {
                        if (key == null) return false;

                        // EnableLUA = 1 → activează UAC global (necesită reboot)
                        key.SetValue("EnableLUA", 1, RegistryValueKind.DWord);

                        // ConsentPromptBehaviorAdmin = 5 → default: "Notify me only when apps try to make changes"
                        key.SetValue("ConsentPromptBehaviorAdmin", 5, RegistryValueKind.DWord);

                        // PromptOnSecureDesktop = 1 → prompt pe secure desktop (recomandat)
                        key.SetValue("PromptOnSecureDesktop", 1, RegistryValueKind.DWord);
                    }
                    return true;
                }
                catch (UnauthorizedAccessException)
                {
                    return false; // Aplicația nu rulează cu drepturi de admin
                }
                catch (Exception)
                {
                    return false;
                }
            });
        }
    }
}