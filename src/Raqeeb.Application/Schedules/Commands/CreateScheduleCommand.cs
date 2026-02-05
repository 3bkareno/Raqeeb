using MediatR;
using Raqeeb.Domain.Entities;
using Raqeeb.Domain.Interfaces;

namespace Raqeeb.Application.Schedules.Commands;

public class CreateScheduleCommand : IRequest<Guid>
{
    public string Name { get; set; } = string.Empty;
    public string? Description { get; set; }
    public Guid TargetId { get; set; }
    public Guid ScanProfileId { get; set; }
    public string CronExpression { get; set; } = string.Empty;
    public bool IsEnabled { get; set; } = true;
    public string? CreatedBy { get; set; }
}

public class CreateScheduleCommandHandler : IRequestHandler<CreateScheduleCommand, Guid>
{
    private readonly IRepository<Schedule> _scheduleRepository;
    private readonly IScheduleService _scheduleService;

    public CreateScheduleCommandHandler(
        IRepository<Schedule> scheduleRepository,
        IScheduleService scheduleService)
    {
        _scheduleRepository = scheduleRepository;
        _scheduleService = scheduleService;
    }

    public async Task<Guid> Handle(CreateScheduleCommand request, CancellationToken cancellationToken)
    {
        var schedule = new Schedule
        {
            Name = request.Name,
            Description = request.Description,
            TargetId = request.TargetId,
            ScanProfileId = request.ScanProfileId,
            CronExpression = request.CronExpression,
            IsEnabled = request.IsEnabled,
            CreatedBy = request.CreatedBy
        };

        await _scheduleRepository.AddAsync(schedule);

        if (schedule.IsEnabled)
        {
            await _scheduleService.CreateRecurringJobAsync(schedule);
        }

        return schedule.Id;
    }
}
