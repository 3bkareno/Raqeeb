using MediatR;
using Raqeeb.Domain.Entities;
using Raqeeb.Domain.Interfaces;

namespace Raqeeb.Application.Schedules.Queries;

public class GetAllSchedulesQuery : IRequest<List<Schedule>>
{
    public string? UserId { get; set; }
}

public class GetAllSchedulesQueryHandler : IRequestHandler<GetAllSchedulesQuery, List<Schedule>>
{
    private readonly IRepository<Schedule> _scheduleRepository;

    public GetAllSchedulesQueryHandler(IRepository<Schedule> scheduleRepository)
    {
        _scheduleRepository = scheduleRepository;
    }

    public async Task<List<Schedule>> Handle(GetAllSchedulesQuery request, CancellationToken cancellationToken)
    {
        var schedules = await _scheduleRepository.GetAllAsync();
        
        // Filter by user if specified (admin can see all)
        if (!string.IsNullOrEmpty(request.UserId))
        {
            var userId = Guid.Parse(request.UserId);
            schedules = schedules.Where(s => s.Target?.OwnerId == userId).ToList();
        }

        return schedules.OrderByDescending(s => s.CreatedAt).ToList();
    }
}
