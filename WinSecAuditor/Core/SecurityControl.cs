namespace WinSecAuditor.Core
{
    public class SecurityControl
    {
        public string Id { get; set; } = string.Empty;

        public string Name { get; set; } = string.Empty;

        public SecurityCategory Category { get; set; }

        public Severity Severity { get; set; }

        public string Description { get; set; } = string.Empty;

        public int Weight { get; set; }

        public bool SupportsRemediation { get; set; }
    }
}