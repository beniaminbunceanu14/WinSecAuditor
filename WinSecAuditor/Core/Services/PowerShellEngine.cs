using System.Diagnostics;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using WinSecAuditor.Core;

namespace WinSecAuditor.Services
{
    public class PowerShellEngine : IPowerShellEngine
    {
        public async Task<PowerShellResult> ExecuteAsync(string script, CancellationToken cancellationToken = default)
        {
            var stopwatch = Stopwatch.StartNew();

            // Setăm codarea pentru a păstra diacriticele și structura textului
            string utf8Command = $"[Console]::OutputEncoding = [System.Text.Encoding]::UTF8; {script}";

            var startInfo = new ProcessStartInfo
            {
                FileName = "powershell.exe",
                Arguments = $"-NoProfile -ExecutionPolicy Bypass -Command \"{utf8Command}\"",
                RedirectStandardOutput = true,
                RedirectStandardError = true,
                UseShellExecute = false,
                CreateNoWindow = true,
                StandardOutputEncoding = Encoding.UTF8,
                StandardErrorEncoding = Encoding.UTF8
            };

            using var process = new Process { StartInfo = startInfo };
            process.Start();

            // Citim asincron pentru a evita blocarea procesului dacă output-ul este prea mare
            var outputTask = process.StandardOutput.ReadToEndAsync(cancellationToken);
            var errorTask = process.StandardError.ReadToEndAsync(cancellationToken);

            // Așteptăm ca procesul să se termine, suportând și anularea prin CancellationToken
            await process.WaitForExitAsync(cancellationToken);

            stopwatch.Stop();

            return new PowerShellResult
            {
                Output = (await outputTask).Trim(),
                Error = (await errorTask).Trim(),
                ExitCode = process.ExitCode,
                Duration = stopwatch.Elapsed
            };
        }
    }
}