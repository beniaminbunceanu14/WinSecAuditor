using System;
using System.Collections.Generic;
using System.Linq;

namespace WinSecAuditor.Core
{
    public class ScanResult
    {
        public DateTime ScanDate { get; set; } = DateTime.Now;

        public DateTime StartedAt { get; set; } = DateTime.Now;

        public DateTime CompletedAt { get; private set; }

        public List<SecurityFinding> Findings { get; set; } = new();

        public int SecurityScore { get; private set; } = 100;

        public int TotalControls => Findings.Count;

        public int PassedControls => Findings.Count(x => x.Status == FindingStatus.Pass);

        public int FailedControls => Findings.Count(x => x.Status == FindingStatus.Fail);

        public int WarningControls => Findings.Count(x => x.Status == FindingStatus.Warning);

        public int CriticalFindings =>
            Findings.Count(x =>
                x.Severity == Severity.Critical &&
                x.Status != FindingStatus.Pass);

        public int HighFindings =>
            Findings.Count(x =>
                x.Severity == Severity.High &&
                x.Status != FindingStatus.Pass);

        public int MediumFindings =>
            Findings.Count(x =>
                x.Severity == Severity.Medium &&
                x.Status != FindingStatus.Pass);

        public int LowFindings =>
            Findings.Count(x =>
                x.Severity == Severity.Low &&
                x.Status != FindingStatus.Pass);

        public void AddFinding(SecurityFinding finding)
        {
            Findings.Add(finding);
        }

        public void Complete()
        {
            CompletedAt = DateTime.Now;
            CalculateScore();
        }

        public int CalculateScore()
        {
            int totalPenalty = Findings
                .Where(f =>
                    f.Status == FindingStatus.Fail ||
                    f.Status == FindingStatus.Warning)
                .Sum(f => f.PenaltyPoints);

            SecurityScore = Math.Clamp(
                100 - totalPenalty,
                0,
                100);

            return SecurityScore;
        }

        public IReadOnlyDictionary<SecurityCategory, int> GetCategoryScores()
        {
            var result = new Dictionary<SecurityCategory, int>();

            foreach (SecurityCategory category in Enum.GetValues<SecurityCategory>())
            {
                var categoryFindings = Findings
                    .Where(f => f.Category == category)
                    .ToList();

                if (categoryFindings.Count == 0)
                {
                    result[category] = 100;
                    continue;
                }

                int penalty = categoryFindings
                    .Where(f =>
                        f.Status == FindingStatus.Fail ||
                        f.Status == FindingStatus.Warning)
                    .Sum(f => f.PenaltyPoints);

                result[category] = Math.Clamp(
                    100 - penalty,
                    0,
                    100);
            }

            return result;
        }

        public string GetScoreStatus()
        {
            return SecurityScore switch
            {
                >= 90 => "Excellent",
                >= 75 => "Good",
                >= 60 => "Attention Required",
                >= 40 => "High Risk",
                _ => "Critical Risk"
            };
        }

        public string GetScoreExplanation()
        {
            var failed = Findings
                .Where(f =>
                    f.Status == FindingStatus.Fail ||
                    f.Status == FindingStatus.Warning)
                .OrderByDescending(f => f.PenaltyPoints)
                .ToList();

            if (failed.Count == 0)
            {
                return "Toate controalele evaluate au trecut cu succes.";
            }

            return $"Scorul este {SecurityScore}/100 deoarece {failed.Count} controale necesită atenție.";
        }
    }
}