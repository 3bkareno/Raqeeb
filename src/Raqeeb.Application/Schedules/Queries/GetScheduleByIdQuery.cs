using MediatR;
using Microsoft.EntityFrameworkCore;
using Raqeeb.Domain.Entities;
using Raqeeb.Infrastructure.Persistence;

namespace Raqeeb.Application.Schedules.Queries;

public class GetScheduleByIdQuery : IRequest<Schedule?>
{
    public Guid Id { get; set; }
}

public class GetScheduleByIdQueryHandler : IRequestHandler<GetScheduleByIdQuery, Schedule?>
{
    private readonly RaqeebDbContext _context;

    public GetScheduleByIdQueryHandler(RaqeebDbContext context)
    {
        _context = context;
    }

    public async Task<Schedule?> Handle(GetScheduleByIdQuery request, CancellationToken cancellationToken)
    {
        return await _context.Schedules
            .Include(s => s.Target)
            .Include(s => s.ScanProfile)
            .FirstOrDefaultAsync(s => s.Id == request.Id, cancellationToken);
    }
}
