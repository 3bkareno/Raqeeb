using MediatR;
using Raqeeb.Domain.Entities;
using Raqeeb.Domain.Interfaces;

namespace Raqeeb.Application.Schedules.Commands;

public class DeleteScheduleCommand : IRequest<Unit>
{
    public Guid Id { get; set; }
}

public class DeleteScheduleCommandHandler : IRequestHandler<DeleteScheduleCommand, Unit>
{
    private readonly IRepository<Schedule> _scheduleRepository;
    private readonly IScheduleService _scheduleService;

    public DeleteScheduleCommandHandler(
        IRepository<Schedule> scheduleRepository,
        IScheduleService scheduleService)
    {
        _scheduleRepository = scheduleRepository;
        _scheduleService = scheduleService;
    }

    public async Task<Unit> Handle(DeleteScheduleCommand request, CancellationToken cancellationToken)
    {
        await _scheduleService.RemoveRecurringJobAsync(request.Id);
        await _scheduleRepository.DeleteAsync(request.Id);
        return Unit.Value;
    }
}
