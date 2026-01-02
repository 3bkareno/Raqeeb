using Microsoft.EntityFrameworkCore;
using Raqeeb.Domain.Entities;

namespace Raqeeb.Infrastructure.Persistence
{
    public class RaqeebDbContext : DbContext
    {
        public RaqeebDbContext(DbContextOptions<RaqeebDbContext> options) : base(options)
        {
        }

        public DbSet<Target> Targets { get; set; }
        public DbSet<ScanJob> ScanJobs { get; set; }
        public DbSet<ScanProfile> ScanProfiles { get; set; }
        public DbSet<Vulnerability> Vulnerabilities { get; set; }

        protected override void OnModelCreating(ModelBuilder modelBuilder)
        {
            base.OnModelCreating(modelBuilder);

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
                      .WithOne() // Assuming Vulnerability doesn't have a nav prop back to ScanJob or it's inferred
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
}
