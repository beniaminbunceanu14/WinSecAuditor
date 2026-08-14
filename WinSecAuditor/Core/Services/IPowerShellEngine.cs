using System.Threading;
using System.Threading.Tasks;
using WinSecAuditor.Core;

namespace WinSecAuditor.Services
{
    public interface IPowerShellEngine
    {
        Task<PowerShellResult> ExecuteAsync(string script, CancellationToken cancellationToken = default);
    }
}