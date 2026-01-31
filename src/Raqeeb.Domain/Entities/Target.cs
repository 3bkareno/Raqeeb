namespace Raqeeb.Domain.Entities;

public class Target
{
    public Guid Id { get; set; } = Guid.NewGuid();
    public string Url { get; set; } = string.Empty;
    public Guid? OwnerId { get; set; } // Links to ApplicationUser
    public DateTime CreatedAt { get; set; } = DateTime.UtcNow;
    public bool IsVerified { get; set; }
    
    // Navigation properties
    public virtual ApplicationUser? Owner { get; set; }
    public virtual ICollection<ScanJob> ScanJobs { get; set; } = new List<ScanJob>();
}
