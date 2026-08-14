using System;

namespace WinSecAuditor.Core
{
    public class PowerShellResult
    {
        public string Output { get; init; } = string.Empty;
        public string Error { get; init; } = string.Empty;
        public int ExitCode { get; init; }
        public TimeSpan Duration { get; init; }

        // Proprietate helper pentru a valida rapid dacă execuția a fost curată
        public bool IsSuccess => ExitCode == 0 && string.IsNullOrEmpty(Error);
    }
}