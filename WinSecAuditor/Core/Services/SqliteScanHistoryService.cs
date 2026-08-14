using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Threading.Tasks;
using Microsoft.Data.Sqlite;
using WinSecAuditor.Core;

namespace WinSecAuditor.Services
{
    /// <summary>
    /// Persistență scan history în SQLite local la %LocalAppData%\WinSecAuditor\history.db.
    /// Tabele: scans (metadate) + findings (detalii per scan, cascade delete).
    /// </summary>
    public class SqliteScanHistoryService : IScanHistoryService
    {
        private readonly string _connectionString;
        private bool _initialized;

        public SqliteScanHistoryService()
        {
            var appDataPath = Path.Combine(
                Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
                "WinSecAuditor");
            Directory.CreateDirectory(appDataPath);

            var dbPath = Path.Combine(appDataPath, "history.db");
            _connectionString = new SqliteConnectionStringBuilder
            {
                DataSource = dbPath,
                Mode = SqliteOpenMode.ReadWriteCreate
            }.ToString();
        }

        public async Task InitializeAsync()
        {
            if (_initialized) return;

            using var conn = new SqliteConnection(_connectionString);
            await conn.OpenAsync();

            var cmd = conn.CreateCommand();
            cmd.CommandText = @"
                CREATE TABLE IF NOT EXISTS scans (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    scan_date TEXT NOT NULL,
                    score INTEGER NOT NULL,
                    status TEXT NOT NULL,
                    total_findings INTEGER NOT NULL,
                    failed_findings INTEGER NOT NULL
                );

                CREATE TABLE IF NOT EXISTS findings (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    scan_id INTEGER NOT NULL,
                    control_id TEXT NOT NULL,
                    category INTEGER NOT NULL,
                    title TEXT NOT NULL,
                    description TEXT,
                    evidence TEXT,
                    recommendation TEXT,
                    severity INTEGER NOT NULL,
                    status INTEGER NOT NULL,
                    FOREIGN KEY (scan_id) REFERENCES scans(id) ON DELETE CASCADE
                );

                CREATE INDEX IF NOT EXISTS idx_findings_scan_id ON findings(scan_id);
                CREATE INDEX IF NOT EXISTS idx_scans_date ON scans(scan_date DESC);
            ";
            await cmd.ExecuteNonQueryAsync();

            _initialized = true;
        }

        public async Task<long> SaveScanAsync(DateTime scanDate, int score, string status, IEnumerable<SecurityFinding> findings)
        {
            await InitializeAsync();

            using var conn = new SqliteConnection(_connectionString);
            await conn.OpenAsync();
            using var tx = conn.BeginTransaction();

            var findingsList = findings.ToList();
            var failed = findingsList.Count(f => !f.IsPassed);

            var scanCmd = conn.CreateCommand();
            scanCmd.Transaction = tx;
            scanCmd.CommandText = @"
                INSERT INTO scans (scan_date, score, status, total_findings, failed_findings)
                VALUES ($date, $score, $status, $total, $failed);
                SELECT last_insert_rowid();
            ";
            scanCmd.Parameters.AddWithValue("$date", scanDate.ToString("o"));
            scanCmd.Parameters.AddWithValue("$score", score);
            scanCmd.Parameters.AddWithValue("$status", status);
            scanCmd.Parameters.AddWithValue("$total", findingsList.Count);
            scanCmd.Parameters.AddWithValue("$failed", failed);

            var scanId = (long)(await scanCmd.ExecuteScalarAsync() ?? 0L);

            foreach (var f in findingsList)
            {
                var fCmd = conn.CreateCommand();
                fCmd.Transaction = tx;
                fCmd.CommandText = @"
                    INSERT INTO findings 
                        (scan_id, control_id, category, title, description, evidence, recommendation, severity, status)
                    VALUES ($sid, $cid, $cat, $title, $desc, $evi, $rec, $sev, $st);
                ";
                fCmd.Parameters.AddWithValue("$sid", scanId);
                fCmd.Parameters.AddWithValue("$cid", f.Id ?? string.Empty);
                fCmd.Parameters.AddWithValue("$cat", (int)f.Category);
                fCmd.Parameters.AddWithValue("$title", f.Title ?? string.Empty);
                fCmd.Parameters.AddWithValue("$desc", (object?)f.Description ?? DBNull.Value);
                fCmd.Parameters.AddWithValue("$evi", (object?)f.Evidence ?? DBNull.Value);
                fCmd.Parameters.AddWithValue("$rec", (object?)f.Recommendation ?? DBNull.Value);
                fCmd.Parameters.AddWithValue("$sev", (int)f.Severity);
                fCmd.Parameters.AddWithValue("$st", (int)f.Status);
                await fCmd.ExecuteNonQueryAsync();
            }

            tx.Commit();
            return scanId;
        }

        public async Task<List<ScanHistoryEntry>> GetRecentScansAsync(int limit = 30)
        {
            await InitializeAsync();

            var result = new List<ScanHistoryEntry>();
            using var conn = new SqliteConnection(_connectionString);
            await conn.OpenAsync();

            var cmd = conn.CreateCommand();
            cmd.CommandText = @"
                SELECT id, scan_date, score, status, total_findings, failed_findings
                FROM scans
                ORDER BY scan_date DESC
                LIMIT $limit;
            ";
            cmd.Parameters.AddWithValue("$limit", limit);

            using var reader = await cmd.ExecuteReaderAsync();
            while (await reader.ReadAsync())
            {
                result.Add(new ScanHistoryEntry
                {
                    Id = reader.GetInt64(0),
                    ScanDate = DateTime.Parse(reader.GetString(1)),
                    Score = reader.GetInt32(2),
                    Status = reader.GetString(3),
                    TotalFindings = reader.GetInt32(4),
                    FailedFindings = reader.GetInt32(5)
                });
            }
            return result;
        }

        public async Task<List<SecurityFinding>> GetScanFindingsAsync(long scanId)
        {
            await InitializeAsync();

            var result = new List<SecurityFinding>();
            using var conn = new SqliteConnection(_connectionString);
            await conn.OpenAsync();

            var cmd = conn.CreateCommand();
            cmd.CommandText = @"
                SELECT control_id, category, title, description, evidence, recommendation, severity, status
                FROM findings
                WHERE scan_id = $sid;
            ";
            cmd.Parameters.AddWithValue("$sid", scanId);

            using var reader = await cmd.ExecuteReaderAsync();
            while (await reader.ReadAsync())
            {
                result.Add(new SecurityFinding
                {
                    Id = reader.GetString(0),
                    Category = (SecurityCategory)reader.GetInt32(1),
                    Title = reader.GetString(2),
                    Description = reader.IsDBNull(3) ? string.Empty : reader.GetString(3),
                    Evidence = reader.IsDBNull(4) ? string.Empty : reader.GetString(4),
                    Recommendation = reader.IsDBNull(5) ? string.Empty : reader.GetString(5),
                    Severity = (Severity)reader.GetInt32(6),
                    Status = (FindingStatus)reader.GetInt32(7),
                    CanRemediate = false // istoric = read-only, nu remediezi trecutul
                });
            }
            return result;
        }

        public async Task DeleteScanAsync(long scanId)
        {
            await InitializeAsync();
            using var conn = new SqliteConnection(_connectionString);
            await conn.OpenAsync();

            using var pragmaCmd = conn.CreateCommand();
            pragmaCmd.CommandText = "PRAGMA foreign_keys = ON;";
            await pragmaCmd.ExecuteNonQueryAsync();

            var cmd = conn.CreateCommand();
            cmd.CommandText = @"
                DELETE FROM findings WHERE scan_id = $sid;
                DELETE FROM scans WHERE id = $sid;
            ";
            cmd.Parameters.AddWithValue("$sid", scanId);
            await cmd.ExecuteNonQueryAsync();
        }
    }
}