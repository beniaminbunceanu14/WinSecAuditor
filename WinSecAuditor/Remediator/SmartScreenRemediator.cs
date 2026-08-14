using System;
using System.Threading.Tasks;
using Microsoft.Win32;

namespace WinSecAuditor.Remediation
{
    /// <summary>
    /// Activează Windows Defender SmartScreen pentru Explorer (fișiere descărcate)
    /// și pentru Microsoft Edge. Necesită drepturi de Administrator.
    /// </summary>
    public class SmartScreenRemediator
    {
        public Task<bool> EnableSmartScreenAsync()
        {
            return Task.Run(() =>
            {
                bool anySuccess = false;

                // 1. SmartScreen pentru Explorer / fișiere descărcate
                try
                {
                    using (RegistryKey? key = Registry.LocalMachine.OpenSubKey(
    @"SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer", writable: true))
                    {
                        if (key != null)
                        {
                            key.SetValue("SmartScreenEnabled", "RequireAdmin", RegistryValueKind.String);
                            anySuccess = true;
                        }
                    }
                }
                catch { /* fallback pe policy key */ }

                // 2. SmartScreen prin Group Policy (mai puternic, prevalează)
                try
                {
                    using (RegistryKey key = Registry.LocalMachine.CreateSubKey(
                        @"SOFTWARE\Policies\Microsoft\Windows\System"))
                    {
                        if (key != null)
                        {
                            key.SetValue("EnableSmartScreen", 1, RegistryValueKind.DWord);
                            key.SetValue("ShellSmartScreenLevel", "Block", RegistryValueKind.String);
                            anySuccess = true;
                        }
                    }
                }
                catch { /* ignore */ }

                // 3. SmartScreen pentru Microsoft Edge
                try
                {
                    using (RegistryKey key = Registry.LocalMachine.CreateSubKey(
                        @"SOFTWARE\Policies\Microsoft\Edge"))
                    {
                        if (key != null)
                        {
                            key.SetValue("SmartScreenEnabled", 1, RegistryValueKind.DWord);
                            key.SetValue("SmartScreenPuaEnabled", 1, RegistryValueKind.DWord);
                            anySuccess = true;
                        }
                    }
                }
                catch { /* ignore */ }

                return anySuccess;
            });
        }
    }
}