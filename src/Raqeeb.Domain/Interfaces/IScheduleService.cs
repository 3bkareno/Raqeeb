using System;
using System.Threading.Tasks;
using Raqeeb.Domain.Entities;

namespace Raqeeb.Domain.Interfaces
{
    public interface IScheduleService
    {
        /// <summary>
        /// Creates a recurring job for the schedule
        /// </summary>
        Task CreateRecurringJobAsync(Schedule schedule);
        
        /// <summary>
        /// Updates an existing recurring job
        /// </summary>
        Task UpdateRecurringJobAsync(Schedule schedule);
        
        /// <summary>
        /// Removes a recurring job
        /// </summary>
        Task RemoveRecurringJobAsync(Guid scheduleId);
        
        /// <summary>
        /// Triggers a scheduled scan immediately
        /// </summary>
        Task TriggerScheduledScanAsync(Guid scheduleId);
    }
}
