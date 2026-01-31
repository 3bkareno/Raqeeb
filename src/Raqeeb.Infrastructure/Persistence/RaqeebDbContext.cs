using Microsoft.AspNetCore.Identity.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore;
using Raqeeb.Domain.Entities;

namespace Raqeeb.Infrastructure.Persistence;

public class RaqeebDbContext : IdentityDbContext<ApplicationUser, ApplicationRole, Guid>
{
    public RaqeebDbContext(DbContextOptions<RaqeebDbContext> options) : base(options)
    {
    }

    public DbSet<Target> Targets { get; set; }
    public DbSet<ScanJob> ScanJobs { get; set; }
    public DbSet<ScanProfile> ScanProfiles { get; set; }
    public DbSet<Vulnerability> Vulnerabilities { get; set; }
    public DbSet<AuditLog> AuditLogs { get; set; }

    protected override void OnModelCreating(ModelBuilder modelBuilder)
    {
        base.OnModelCreating(modelBuilder);

        // Rename Identity tables to be more readable
        modelBuilder.Entity<ApplicationUser>(entity =>
        {
            entity.ToTable("Users");
            entity.HasMany(u => u.Targets)
                  .WithOne(t => t.Owner)
                  .HasForeignKey(t => t.OwnerId)
                  .OnDelete(DeleteBehavior.SetNull);
        });

        modelBuilder.Entity<AuditLog>(entity =>
        {
            entity.ToTable("AuditLogs");
            entity.HasKey(e => e.Id);
            entity.HasIndex(e => e.Timestamp);
            entity.HasIndex(e => e.UserId);
            entity.HasIndex(e => e.Action);
            entity.HasOne(e => e.User)
                  .WithMany()
                  .HasForeignKey(e => e.UserId)
                  .OnDelete(DeleteBehavior.SetNull);
        });

        modelBuilder.Entity<ApplicationRole>(entity =>
        {
            entity.ToTable("Roles");
        });

        modelBuilder.Entity<Target>(entity =>
        {
            entity.HasKey(e => e.Id);
            entity.Property(e => e.Url).IsRequired();
            entity.HasMany(e => e.ScanJobs)
                  .WithOne(e => e.Target)
                  .HasForeignKey(e => e.TargetId)
                  .OnDelete(DeleteBehavior.Cascade);
        });

        modelBuilder.Entity<ScanJob>(entity =>
        {
            entity.HasKey(e => e.Id);
            entity.HasOne(e => e.ScanProfile)
                  .WithMany()
                  .HasForeignKey(e => e.ScanProfileId);
            
            entity.HasMany(e => e.Vulnerabilities)
                  .WithOne()
                  .HasForeignKey(e => e.ScanJobId)
                  .OnDelete(DeleteBehavior.Cascade);
        });

        modelBuilder.Entity<ScanProfile>(entity =>
        {
            entity.HasKey(e => e.Id);
        });

        modelBuilder.Entity<Vulnerability>(entity =>
        {
            entity.HasKey(e => e.Id);
        });
    }
}
