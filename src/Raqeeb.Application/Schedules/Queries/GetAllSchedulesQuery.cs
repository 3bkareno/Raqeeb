using MediatR;
using Microsoft.EntityFrameworkCore;
using Raqeeb.Domain.Entities;
using Raqeeb.Domain.Interfaces;
using Raqeeb.Infrastructure.Persistence;

namespace Raqeeb.Application.Schedules.Queries;

public class GetAllSchedulesQuery : IRequest<List<Schedule>>
{
    public string? UserId { get; set; }
}

public class GetAllSchedulesQueryHandler : IRequestHandler<GetAllSchedulesQuery, List<Schedule>>
{
    private readonly RaqeebDbContext _context;

    public GetAllSchedulesQueryHandler(RaqeebDbContext context)
    {
        _context = context;
    }

    public async Task<List<Schedule>> Handle(GetAllSchedulesQuery request, CancellationToken cancellationToken)
    {
        var query = _context.Schedules
            .Include(s => s.Target)
            .Include(s => s.ScanProfile)
            .AsQueryable();

        // Filter by user if specified (admin can see all)
        if (!string.IsNullOrEmpty(request.UserId))
        {
            var userId = Guid.Parse(request.UserId);
            query = query.Where(s => s.Target!.OwnerId == userId);
        }

        return await query
            .OrderByDescending(s => s.CreatedAt)
            .ToListAsync(cancellationToken);
    }
}
