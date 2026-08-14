using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.IO;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Input;
using System.Windows.Media;
using System.Windows.Shapes;
using System.Threading.Tasks;
using WinSecAuditor.Core;
using WinSecAuditor.Services;
using WinSecAuditor.Auditing;
using WinSecAuditor.Remediation;

namespace WinSecAuditor
{
    public partial class MainWindow : Window
    {
        private readonly IPowerShellEngine _psEngine;

        private readonly ISecurityAuditor _defenderAuditor;
        private readonly ISecurityAuditor _networkAuditor;
        private readonly ISecurityAuditor _startupAuditor;
        private readonly ISecurityAuditor _bitLockerAuditor;
        private readonly ISecurityAuditor _uacAuditor;
        private readonly ISecurityAuditor _secureBootAuditor;
        private readonly ISecurityAuditor _smartScreenAuditor;
        private readonly ISecurityAuditor _powerShellAuditor;

        private readonly FirewallRemediator _firewallRemediator;
        private readonly UacRemediator _uacRemediator;
        private readonly SmartScreenRemediator _smartScreenRemediator;
        private readonly PowerShellPolicyRemediator _powerShellRemediator;

        private readonly Dictionary<string, Func<Task<bool>>> _remediations;
        private readonly IScanHistoryService _historyService;

        private List<SecurityFinding> _lastFindings = new List<SecurityFinding>();
        private List<ScanHistoryEntry> _currentHistoryScans = new List<ScanHistoryEntry>();
        private int _lastScore = 0;

        public MainWindow()
        {
            InitializeComponent();

            _psEngine = new PowerShellEngine();

            _defenderAuditor = new DefenderAuditor(_psEngine);
            _networkAuditor = new NetworkAuditor(_psEngine);
            _startupAuditor = new StartupAuditor(_psEngine);
            _bitLockerAuditor = new BitLockerAuditor(_psEngine);
            _uacAuditor = new UacAuditor(_psEngine);
            _secureBootAuditor = new SecureBootAuditor(_psEngine);
            _smartScreenAuditor = new SmartScreenAuditor(_psEngine);
            _powerShellAuditor = new PowerShellExecutionPolicyAuditor(_psEngine);

            _firewallRemediator = new FirewallRemediator(_psEngine);
            _uacRemediator = new UacRemediator();
            _smartScreenRemediator = new SmartScreenRemediator();
            _powerShellRemediator = new PowerShellPolicyRemediator(_psEngine);


            _remediations = new Dictionary<string, Func<Task<bool>>>(StringComparer.OrdinalIgnoreCase)
            {
                ["NET-001"] = () => _firewallRemediator.BlockPortAsync(445, "WinSecAuditor - Block SMB 445"),
                ["NET-002"] = () => _firewallRemediator.BlockPortAsync(3389, "WinSecAuditor - Block RDP 3389"),
                ["SYS-001"] = () => _uacRemediator.EnableUacAsync(),
                ["SYS-003"] = () => _smartScreenRemediator.EnableSmartScreenAsync(),
                ["SYS-004"] = () => _powerShellRemediator.SetSecurePolicyAsync(),
            };

            _historyService = new SqliteScanHistoryService();

            HighlightActiveMenu(BtnNavDashboard);

            // Verifică dacă rulăm ca Administrator
            try
            {
                var identity = System.Security.Principal.WindowsIdentity.GetCurrent();
                var principal = new System.Security.Principal.WindowsPrincipal(identity);
                bool isAdmin = principal.IsInRole(System.Security.Principal.WindowsBuiltInRole.Administrator);

                TxtPrivilege.Text = isAdmin ? "Administrator" : "Standard User";
                PrivilegeDot.Fill = new SolidColorBrush(isAdmin
                    ? Color.FromRgb(38, 222, 129)  // green
                    : Color.FromRgb(255, 71, 87)); // red
            }
            catch { /* leave defaults */ }

            // Init DB + repaint sparkline la resize
            Loaded += async (s, e) => await _historyService.InitializeAsync();
            SparklineCanvas.SizeChanged += (s, e) => DrawSparkline(_currentHistoryScans);
        }

        // ===================== AUDIT =====================

        private async void BtnRunAudit_Click(object sender, RoutedEventArgs e)
        {
            await RunFullAuditAsync();
        }

        private async Task RunFullAuditAsync()
        {
            BtnRunAudit.IsEnabled = false;
            BtnRunAudit.Content = "SCANNING...";
            TxtStatus.Text = "Running security modules...";
            TxtStatus.Foreground = Brushes.White;

            var auditors = new (string Name, ISecurityAuditor Auditor)[]
            {
                ("Windows Defender",     _defenderAuditor),
                ("Network & Firewall",   _networkAuditor),
                ("Startup & Persistence",_startupAuditor),
                ("BitLocker",            _bitLockerAuditor),
                ("UAC",                  _uacAuditor),
                ("Secure Boot",          _secureBootAuditor),
                ("SmartScreen",          _smartScreenAuditor),
                ("PowerShell Policy",    _powerShellAuditor),
            };

            var tasks = auditors.Select(a => SafeRunAsync(a.Name, a.Auditor)).ToArray();
            var results = await Task.WhenAll(tasks);
            _lastFindings = results.SelectMany(r => r).ToList();

            var scanResult = new ScanResult { ScanDate = DateTime.Now, Findings = _lastFindings };
            _lastScore = scanResult.CalculateScore();

            TxtScore.Text = _lastScore.ToString();

            // Culoare status + progress bar
            Color statusColor;
            string statusLabel;
            if (_lastScore >= 90) { statusLabel = "Secure"; statusColor = Color.FromRgb(38, 222, 129); }
            else if (_lastScore >= 70) { statusLabel = "Attention Required"; statusColor = Color.FromRgb(255, 159, 67); }
            else { statusLabel = "Vulnerable"; statusColor = Color.FromRgb(255, 71, 87); }

            TxtStatus.Text = statusLabel;
            TxtStatus.Foreground = new SolidColorBrush(statusColor);
            ScoreFillBar.Fill = new SolidColorBrush(statusColor);

            // Progress bar width (bind manual la ActualWidth)
            void UpdateBarWidth()
            {
                if (ScoreFillBarBg.ActualWidth > 0)
                    ScoreFillBar.Width = (_lastScore / 100.0) * ScoreFillBarBg.ActualWidth;
            }
            UpdateBarWidth();
            ScoreFillBarBg.SizeChanged += (s, e) => UpdateBarWidth();

            // KPI tiles
            TxtKpiCritical.Text = _lastFindings.Count(f => !f.IsPassed && f.Severity == Severity.Critical).ToString();
            TxtKpiHigh.Text = _lastFindings.Count(f => !f.IsPassed && f.Severity == Severity.High).ToString();
            TxtKpiMedium.Text = _lastFindings.Count(f => !f.IsPassed && f.Severity == Severity.Medium).ToString();
            TxtKpiPassed.Text = _lastFindings.Count(f => f.IsPassed).ToString();

            // Last scan caption
            TxtLastScanCaption.Text = $"Ultimul scan: {scanResult.ScanDate:HH:mm:ss} · {_lastFindings.Count} controale evaluate";

            // Persistă scan-ul în istoric (fail-safe: nu blochează UI dacă DB pică)
            try
            {
                await _historyService.SaveScanAsync(scanResult.ScanDate, _lastScore, statusLabel, _lastFindings);

                if (ViewHistory.Visibility == Visibility.Visible)
                {
                    await LoadHistoryAsync();
                }
            }
            catch (Exception ex)
            {
                System.Diagnostics.Debug.WriteLine($"Persistență scan history eșuată: {ex.Message}");
            }

            SwitchToCategoryView(BtnNavDashboard, "Security Overview", null);

            if (ViewHardening.Visibility == Visibility.Visible)
            {
                RefreshHardeningView();
            }

            BtnRunAudit.IsEnabled = true;
            BtnRunAudit.Content = "RUN FULL AUDIT";
        }

        private static async Task<List<SecurityFinding>> SafeRunAsync(string moduleName, ISecurityAuditor auditor)
        {
            try
            {
                var results = await auditor.RunAuditAsync();
                return results?.ToList() ?? new List<SecurityFinding>();
            }
            catch (Exception ex)
            {
                return new List<SecurityFinding>
                {
                    new SecurityFinding
                    {
                        Id             = $"ERR-{moduleName.Replace(" ", "").ToUpperInvariant()}",
                        Title          = $"Eroare modul: {moduleName}",
                        Description    = $"Modulul de audit a eșuat: {ex.Message}",
                        Recommendation = "Rulează aplicația ca Administrator sau verifică log-urile.",
                        Category       = SecurityCategory.WindowsSecurity,
                        Severity       = Severity.Medium,
                        Status         = FindingStatus.Fail,
                        CanRemediate   = false,
                    }
                };
            }
        }

        // ===================== NAVIGARE =====================

        private void BtnNavDashboard_Click(object sender, RoutedEventArgs e)
            => SwitchToCategoryView(BtnNavDashboard, "Security Overview", null);

        private void BtnNavWindowsSec_Click(object sender, RoutedEventArgs e)
            => SwitchToCategoryView(BtnNavWindowsSec, "Windows Security", SecurityCategory.WindowsSecurity);

        private void BtnNavNetwork_Click(object sender, RoutedEventArgs e)
            => SwitchToCategoryView(BtnNavNetwork, "Network & Firewall", SecurityCategory.Network);

        private void BtnNavStartup_Click(object sender, RoutedEventArgs e)
            => SwitchToCategoryView(BtnNavStartup, "Startup & Processes", SecurityCategory.Startup);

        private void SwitchToCategoryView(Button activeBtn, string viewTitle, SecurityCategory? filterCategory)
        {
            ViewDashboard.Visibility = Visibility.Visible;
            ViewHardening.Visibility = Visibility.Collapsed;
            ViewHistory.Visibility = Visibility.Collapsed;
            HighlightActiveMenu(activeBtn);

            TxtCategoryTitle.Text = viewTitle;

            if (_lastFindings.Any())
            {
                var query = _lastFindings.AsEnumerable();

                if (filterCategory.HasValue)
                {
                    query = query.Where(f => f.Category == filterCategory.Value);
                }

                ListFindings.ItemsSource = query
                    .OrderBy(f => f.IsPassed)
                    .ThenByDescending(f => (int)f.Severity)
                    .ToList();
            }
        }

        private void BtnNavHardening_Click(object sender, RoutedEventArgs e)
        {
            ViewDashboard.Visibility = Visibility.Collapsed;
            ViewHardening.Visibility = Visibility.Visible;
            ViewHistory.Visibility = Visibility.Collapsed;
            HighlightActiveMenu(BtnNavHardening);
            RefreshHardeningView();
        }

        private async void BtnNavHistory_Click(object sender, RoutedEventArgs e)
        {
            ViewDashboard.Visibility = Visibility.Collapsed;
            ViewHardening.Visibility = Visibility.Collapsed;
            ViewHistory.Visibility = Visibility.Visible;
            HighlightActiveMenu(BtnNavHistory);
            await LoadHistoryAsync();
        }

        private void HighlightActiveMenu(Button activeBtn)
        {
            BtnNavDashboard.Tag = null;
            BtnNavWindowsSec.Tag = null;
            BtnNavNetwork.Tag = null;
            BtnNavStartup.Tag = null;
            BtnNavHardening.Tag = null;
            BtnNavHistory.Tag = null;
            activeBtn.Tag = "Active";
        }

        // ===================== HARDENING =====================

        private void RefreshHardeningView()
        {
            var remediable = _lastFindings
                .Where(f => !f.IsPassed && f.CanRemediate)
                .ToList();

            ListRemediations.ItemsSource = remediable;
            PnlHardeningEmpty.Visibility = remediable.Count == 0
                ? Visibility.Visible
                : Visibility.Collapsed;
        }

        private async void BtnApplyFix_Click(object sender, RoutedEventArgs e)
        {
            if (sender is not Button btn || btn.Tag is not string findingId) return;

            if (!_remediations.TryGetValue(findingId, out var fixAction))
            {
                MessageBox.Show(
                    $"Nu există o remediere înregistrată pentru finding-ul '{findingId}'.\n\n" +
                    "Adaugă maparea în _remediations din MainWindow.",
                    "Hardening Center",
                    MessageBoxButton.OK,
                    MessageBoxImage.Warning);
                return;
            }

            btn.IsEnabled = false;
            btn.Content = "APPLYING...";

            bool success = false;
            string? errorMsg = null;

            try
            {
                success = await fixAction();
            }
            catch (Exception ex)
            {
                errorMsg = ex.Message;
            }

            if (success)
            {
                MessageBox.Show(
                    "Remedierea a fost aplicată cu succes! Se rulează un scan de validare...",
                    "Hardening Center",
                    MessageBoxButton.OK,
                    MessageBoxImage.Information);
                await RunFullAuditAsync();
            }
            else
            {
                MessageBox.Show(
                    $"Nu s-a putut aplica remedierea.\n\n" +
                    $"{(errorMsg != null ? $"Detalii: {errorMsg}\n\n" : "")}" +
                    "Asigură-te că aplicația rulează ca Administrator.",
                    "Eroare",
                    MessageBoxButton.OK,
                    MessageBoxImage.Error);
                btn.IsEnabled = true;
                btn.Content = "APPLY FIX";
            }
        }

        // ===================== SCAN HISTORY =====================

        private async Task LoadHistoryAsync()
        {
            try
            {
                _currentHistoryScans = await _historyService.GetRecentScansAsync(30);
            }
            catch (Exception ex)
            {
                MessageBox.Show($"Nu s-a putut încărca istoricul: {ex.Message}", "Scan History", MessageBoxButton.OK, MessageBoxImage.Error);
                _currentHistoryScans = new List<ScanHistoryEntry>();
            }

            if (_currentHistoryScans.Count == 0)
            {
                ListScanHistory.ItemsSource = null;
                ListHistoricalFindings.ItemsSource = null;
                TxtHistoryPlaceholder.Visibility = Visibility.Collapsed;
                PnlHistoryEmpty.Visibility = Visibility.Visible;
                SparklineCanvas.Children.Clear();
                return;
            }

            PnlHistoryEmpty.Visibility = Visibility.Collapsed;
            TxtHistoryPlaceholder.Visibility = Visibility.Visible;
            ListHistoricalFindings.ItemsSource = null;

            ListScanHistory.ItemsSource = _currentHistoryScans;
            DrawSparkline(_currentHistoryScans);
        }

        private async void ScanHistoryItem_Click(object sender, MouseButtonEventArgs e)
        {
            if (sender is not Border border || border.Tag is not long scanId) return;

            try
            {
                var findings = await _historyService.GetScanFindingsAsync(scanId);
                ListHistoricalFindings.ItemsSource = findings
                    .OrderBy(f => f.IsPassed)
                    .ThenByDescending(f => (int)f.Severity)
                    .ToList();
                TxtHistoryPlaceholder.Visibility = Visibility.Collapsed;
            }
            catch (Exception ex)
            {
                MessageBox.Show($"Nu s-au putut încărca detaliile: {ex.Message}", "Scan History", MessageBoxButton.OK, MessageBoxImage.Error);
            }
        }

        /// <summary>
        /// Desenează graficul de tendință pe canvas: linie de scor + puncte colorate + linii threshold.
        /// </summary>
        private void DrawSparkline(List<ScanHistoryEntry> scans)
        {
            SparklineCanvas.Children.Clear();
            if (scans == null || scans.Count == 0) return;

            var ordered = scans.Take(15).OrderBy(s => s.ScanDate).ToList();

            double width = SparklineCanvas.ActualWidth;
            double height = SparklineCanvas.ActualHeight > 0 ? SparklineCanvas.ActualHeight : 110;
            if (width <= 0) return;

            double padding = 14;
            double plotHeight = height - 2 * padding;
            double ScoreToY(int score) => padding + (100 - Math.Clamp(score, 0, 100)) * plotHeight / 100.0;

            // Grid lines: 0, 25, 50, 75, 100
            var gridBrush = new SolidColorBrush(Color.FromArgb(60, 90, 100, 120));
            for (int val = 0; val <= 100; val += 25)
            {
                double y = ScoreToY(val);
                SparklineCanvas.Children.Add(new Line
                {
                    X1 = 30,
                    X2 = width,
                    Y1 = y,
                    Y2 = y,
                    Stroke = gridBrush,
                    StrokeThickness = 1,
                    StrokeDashArray = new DoubleCollection { 2, 4 }
                });
                SparklineCanvas.Children.Add(BuildLabel(val.ToString(), 4, y - 7, "#5A6478", 10));
            }

            // Threshold lines highlighted
            SparklineCanvas.Children.Add(new Line
            {
                X1 = 30,
                X2 = width,
                Y1 = ScoreToY(90),
                Y2 = ScoreToY(90),
                Stroke = new SolidColorBrush(Color.FromArgb(140, 38, 222, 129)),
                StrokeThickness = 1,
                StrokeDashArray = new DoubleCollection { 4, 4 }
            });
            SparklineCanvas.Children.Add(new Line
            {
                X1 = 30,
                X2 = width,
                Y1 = ScoreToY(70),
                Y2 = ScoreToY(70),
                Stroke = new SolidColorBrush(Color.FromArgb(140, 255, 159, 67)),
                StrokeThickness = 1,
                StrokeDashArray = new DoubleCollection { 4, 4 }
            });

            double plotLeft = 30;
            double plotRight = width - 8;

            if (ordered.Count == 1)
            {
                DrawDot((plotLeft + plotRight) / 2, ScoreToY(ordered[0].Score), ordered[0].Score, true);
                return;
            }

            double stepX = (plotRight - plotLeft) / (ordered.Count - 1);

            // Area fill sub linie (semi-transparent)
            var areaPoints = new PointCollection();
            areaPoints.Add(new Point(plotLeft, height - padding));
            for (int i = 0; i < ordered.Count; i++)
                areaPoints.Add(new Point(plotLeft + i * stepX, ScoreToY(ordered[i].Score)));
            areaPoints.Add(new Point(plotLeft + (ordered.Count - 1) * stepX, height - padding));

            var area = new Polygon
            {
                Points = areaPoints,
                Fill = new SolidColorBrush(Color.FromArgb(35, 79, 143, 255))
            };
            SparklineCanvas.Children.Add(area);

            // Linia principală
            var polyline = new Polyline
            {
                Stroke = new SolidColorBrush(Color.FromRgb(79, 143, 255)),
                StrokeThickness = 2.5,
                StrokeLineJoin = PenLineJoin.Round
            };
            for (int i = 0; i < ordered.Count; i++)
                polyline.Points.Add(new Point(plotLeft + i * stepX, ScoreToY(ordered[i].Score)));
            SparklineCanvas.Children.Add(polyline);

            // Puncte
            for (int i = 0; i < ordered.Count; i++)
            {
                double x = plotLeft + i * stepX;
                double y = ScoreToY(ordered[i].Score);
                DrawDot(x, y, ordered[i].Score, i == ordered.Count - 1);
            }
        }

        private void DrawDot(double x, double y, int score, bool isCurrent)
        {
            Color color = score >= 90 ? Color.FromRgb(38, 222, 129) :
                          score >= 70 ? Color.FromRgb(255, 159, 67) :
                                        Color.FromRgb(255, 71, 87);

            if (isCurrent)
            {
                // Halo exterior
                var halo = new Ellipse { Width = 16, Height = 16, Fill = new SolidColorBrush(Color.FromArgb(60, color.R, color.G, color.B)) };
                Canvas.SetLeft(halo, x - 8); Canvas.SetTop(halo, y - 8);
                SparklineCanvas.Children.Add(halo);
            }

            double size = isCurrent ? 10 : 6;
            var dot = new Ellipse
            {
                Width = size,
                Height = size,
                Fill = new SolidColorBrush(color),
                Stroke = isCurrent ? new SolidColorBrush(Color.FromRgb(10, 12, 16)) : null,
                StrokeThickness = isCurrent ? 2 : 0
            };
            Canvas.SetLeft(dot, x - size / 2); Canvas.SetTop(dot, y - size / 2);
            SparklineCanvas.Children.Add(dot);
        }

        private static TextBlock BuildLabel(string text, double x, double y, string hexColor, double fontSize = 10)
        {
            var tb = new TextBlock
            {
                Text = text,
                FontSize = fontSize,
                Foreground = new SolidColorBrush((Color)ColorConverter.ConvertFromString(hexColor)),
                FontWeight = FontWeights.SemiBold
            };
            Canvas.SetLeft(tb, x); Canvas.SetTop(tb, y);
            return tb;
        }

        // ===================== EXPORT HTML =====================

        private void BtnExport_Click(object sender, RoutedEventArgs e)
        {
            if (!_lastFindings.Any())
            {
                MessageBox.Show("Vă rugăm să rulați un audit înainte de a exporta raportul.", "Nicio dată", MessageBoxButton.OK, MessageBoxImage.Warning);
                return;
            }

            try
            {
                string desktopPath = Environment.GetFolderPath(Environment.SpecialFolder.Desktop);
                string filePath = System.IO.Path.Combine(desktopPath, "WinSec_Audit_Report.html");

                StringBuilder html = new StringBuilder();
                html.AppendLine("<!DOCTYPE html><html><head><meta charset='utf-8'><title>WinSec Security Report</title>");
                html.AppendLine("<style>");
                html.AppendLine("body { font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; background-color: #0D0F12; color: #E0E0E0; margin: 40px; }");
                html.AppendLine("h1 { color: #FFFFFF; border-bottom: 2px solid #1F232B; padding-bottom: 10px; }");
                html.AppendLine(".score-panel { background-color: #1A1D24; padding: 20px; border-radius: 8px; margin-bottom: 30px; font-size: 24px; font-weight: bold; }");
                html.AppendLine(".card { background-color: #13161A; border: 1px solid #1F232B; border-radius: 6px; padding: 20px; margin-bottom: 15px; }");
                html.AppendLine(".pass { border-left: 5px solid #104A25; }");
                html.AppendLine(".fail { border-left: 5px solid #7A1515; }");
                html.AppendLine("h3 { margin-top: 0; }");
                html.AppendLine(".status-pass { color: #4CAF50; } .status-fail { color: #F44336; }");
                html.AppendLine("</style></head><body>");

                html.AppendLine("<h1>WinSec Auditor - Security Posture Report</h1>");
                html.AppendLine($"<div class='score-panel'>Security Score: {_lastScore} / 100 <br><span style='font-size: 14px; font-weight: normal; color: #A0AABF;'>Data generării: {DateTime.Now}</span></div>");
                html.AppendLine("<h2>Detalii Vulnerabilități:</h2>");

                foreach (var finding in _lastFindings.OrderBy(f => f.IsPassed).ThenByDescending(f => (int)f.Severity))
                {
                    string cardClass = finding.IsPassed ? "card pass" : "card fail";
                    string titleColor = finding.IsPassed ? "status-pass" : "status-fail";
                    string statusText = finding.IsPassed ? "PASS" : "FAIL";

                    html.AppendLine($"<div class='{cardClass}'>");
                    html.AppendLine($"<h3 class='{titleColor}'>[{statusText}] {finding.Title} (Severitate: {finding.Severity})</h3>");
                    html.AppendLine($"<p>{finding.Description}</p>");

                    if (!finding.IsPassed && !string.IsNullOrEmpty(finding.Recommendation))
                    {
                        html.AppendLine($"<p><strong>Recomandare:</strong> {finding.Recommendation}</p>");
                    }
                    html.AppendLine("</div>");
                }

                html.AppendLine("</body></html>");

                File.WriteAllText(filePath, html.ToString(), Encoding.UTF8);

                MessageBox.Show($"Raportul HTML a fost generat cu succes pe Desktop:\n\n{filePath}", "Export Finalizat", MessageBoxButton.OK, MessageBoxImage.Information);
            }
            catch (Exception ex)
            {
                MessageBox.Show($"A apărut o eroare la salvarea raportului: {ex.Message}", "Eroare Export", MessageBoxButton.OK, MessageBoxImage.Error);
            }
        }
    }
}