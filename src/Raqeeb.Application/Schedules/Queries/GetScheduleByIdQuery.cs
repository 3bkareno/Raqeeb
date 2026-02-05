using MediatR;
using Raqeeb.Domain.Entities;
using Raqeeb.Domain.Interfaces;

namespace Raqeeb.Application.Schedules.Queries;

public class GetScheduleByIdQuery : IRequest<Schedule?>
{
    public Guid Id { get; set; }
}

public class GetScheduleByIdQueryHandler : IRequestHandler<GetScheduleByIdQuery, Schedule?>
{
    private readonly IRepository<Schedule> _scheduleRepository;

    public GetScheduleByIdQueryHandler(IRepository<Schedule> scheduleRepository)
    {
        _scheduleRepository = scheduleRepository;
    }

    public async Task<Schedule?> Handle(GetScheduleByIdQuery request, CancellationToken cancellationToken)
    {
        return await _scheduleRepository.GetByIdAsync(request.Id);
    }
}
