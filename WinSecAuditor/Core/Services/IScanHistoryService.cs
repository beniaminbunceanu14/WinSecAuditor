using System;
using System.Collections.Generic;
using System.Threading.Tasks;
using WinSecAuditor.Core;

namespace WinSecAuditor.Services
{
    /// <summary>DTO folosit pentru afișarea listei de scan-uri istorice.</summary>
    public class ScanHistoryEntry
    {
        public long Id { get; set; }
        public DateTime ScanDate { get; set; }
        public int Score { get; set; }
        public string Status { get; set; } = string.Empty;
        public int TotalFindings { get; set; }
        public int FailedFindings { get; set; }
    }

    public interface IScanHistoryService
    {
        Task InitializeAsync();
        Task<long> SaveScanAsync(DateTime scanDate, int score, string status, IEnumerable<SecurityFinding> findings);
        Task<List<ScanHistoryEntry>> GetRecentScansAsync(int limit = 30);
        Task<List<SecurityFinding>> GetScanFindingsAsync(long scanId);
        Task DeleteScanAsync(long scanId);
    }
}