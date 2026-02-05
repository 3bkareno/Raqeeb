using MediatR;
using Raqeeb.Domain.Entities;
using Raqeeb.Domain.Interfaces;

namespace Raqeeb.Application.Schedules.Commands;

public class UpdateScheduleCommand : IRequest<Unit>
{
    public Guid Id { get; set; }
    public string Name { get; set; } = string.Empty;
    public string? Description { get; set; }
    public string CronExpression { get; set; } = string.Empty;
    public bool IsEnabled { get; set; }
}

public class UpdateScheduleCommandHandler : IRequestHandler<UpdateScheduleCommand, Unit>
{
    private readonly IRepository<Schedule> _scheduleRepository;
    private readonly IScheduleService _scheduleService;

    public UpdateScheduleCommandHandler(
        IRepository<Schedule> scheduleRepository,
        IScheduleService scheduleService)
    {
        _scheduleRepository = scheduleRepository;
        _scheduleService = scheduleService;
    }

    public async Task<Unit> Handle(UpdateScheduleCommand request, CancellationToken cancellationToken)
    {
        var schedule = await _scheduleRepository.GetByIdAsync(request.Id);
        if (schedule == null)
        {
            throw new InvalidOperationException($"Schedule {request.Id} not found");
        }

        schedule.Name = request.Name;
        schedule.Description = request.Description;
        schedule.CronExpression = request.CronExpression;
        schedule.IsEnabled = request.IsEnabled;

        await _scheduleRepository.UpdateAsync(schedule);
        await _scheduleService.UpdateRecurringJobAsync(schedule);

        return Unit.Value;
    }
}
