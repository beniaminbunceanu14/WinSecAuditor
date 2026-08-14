using System.Collections.Generic;

namespace WinSecAuditor.Core
{
    public class SecurityEvidence
    {
        public string RawData { get; set; } = string.Empty;
        public Dictionary<string, string> KeyValues { get; set; } = new();
        public bool IsCollectedSuccessfully { get; set; } = true;
        public string ErrorMessage { get; set; } = string.Empty;
    }
}