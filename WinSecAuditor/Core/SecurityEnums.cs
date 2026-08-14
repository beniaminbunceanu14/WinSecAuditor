namespace WinSecAuditor.Core
{
    public enum FindingStatus
    {
        Pass,
        Fail,
        Warning,
        NotAssessed,
        Error
    }

    public enum Severity
    {
        Info,
        Low,
        Medium,
        High,
        Critical
    }

    public enum SecurityCategory
    {
        WindowsSecurity,
        Network,
        Firewall,
        Startup,
        Processes,
        Encryption,
        SystemConfiguration
    }
}