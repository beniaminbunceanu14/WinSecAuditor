using System.Collections.Generic;
using System.Threading;
using System.Threading.Tasks;
using WinSecAuditor.Core;

namespace WinSecAuditor.Auditing
{
    public interface ISecurityAuditor
    {
        string AuditorName { get; }

        Task<List<SecurityFinding>> RunAuditAsync(CancellationToken cancellationToken = default);
    }
}