using System;

namespace WinSecAuditor.Core
{
    public class SecurityFinding
    {
        public string Id { get; set; } = string.Empty;

        public string Title { get; set; } = string.Empty;

        public SecurityCategory Category { get; set; }

        private FindingStatus _status = FindingStatus.NotAssessed;
        public FindingStatus Status
        {
            get => _status;
            set
            {
                _status = value;
                _isPassed = (_status == FindingStatus.Pass);
            }
        }

        private bool _isPassed;
        public bool IsPassed
        {
            get => _isPassed;
            set
            {
                _isPassed = value;
                _status = value ? FindingStatus.Pass : FindingStatus.Fail;
            }
        }

        public bool IsPassing => IsPassed;

        public Severity Severity { get; set; } = Severity.Medium;

        public string Description { get; set; } = string.Empty;

        public string Evidence { get; set; } = string.Empty;

        public string Recommendation { get; set; } = string.Empty;

        public string? RemediationId { get; set; }

        public bool CanRemediate { get; set; }

        public int PenaltyPoints { get; set; } = 10;

        public DateTime Timestamp { get; set; } = DateTime.Now;

        public bool RequiresAttention => !IsPassed;
    }
}