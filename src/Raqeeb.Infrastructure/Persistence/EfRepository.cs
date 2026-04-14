using System;
using System.Collections.Generic;
using System.Linq;
using System.Linq.Expressions;
using System.Threading.Tasks;
using Microsoft.EntityFrameworkCore;
using Raqeeb.Domain.Interfaces;

namespace Raqeeb.Infrastructure.Persistence
{
    public class EfRepository<T> : IRepository<T> where T : class
    {
        private readonly RaqeebDbContext _context;
        private readonly DbSet<T> _dbSet;

        public EfRepository(RaqeebDbContext context)
        {
            _context = context;
            _dbSet = context.Set<T>();
        }

        public async Task<T?> GetByIdAsync(Guid id)
        {
            return await _dbSet.FindAsync(id);
        }

        public async Task<T?> GetByIdFreshAsync(Guid id)
        {
            // Detach the tracked entity if present so the query hits the database
            var tracked = _dbSet.Local.FirstOrDefault(e => _context.Entry(e).Property("Id").CurrentValue is Guid g && g == id);
            if (tracked != null)
            {
                _context.Entry(tracked).State = EntityState.Detached;
            }

            return await _dbSet.FindAsync(id);
        }

        public async Task<IEnumerable<T>> GetAllAsync()
        {
            return await _dbSet.ToListAsync();
        }

        public async Task<IEnumerable<T>> FindAsync(Expression<Func<T, bool>> predicate)
        {
            return await _dbSet.Where(predicate).ToListAsync();
        }

        public async Task AddAsync(T entity)
        {
            await _dbSet.AddAsync(entity);
            await _context.SaveChangesAsync();
        }

        public async Task UpdateAsync(T entity)
        {
            // Detach any existing tracked entity with the same ID to avoid tracking conflicts
            var tracked = _dbSet.Local.FirstOrDefault(e => 
                _context.Entry(e).Property("Id").CurrentValue is Guid id && 
                id.Equals(_context.Entry(entity).Property("Id").CurrentValue));

            if (tracked != null)
            {
                _context.Entry(tracked).State = EntityState.Detached;
            }

            _dbSet.Update(entity);
            await _context.SaveChangesAsync();
        }

        public async Task DeleteAsync(T entity)
        {
            _dbSet.Remove(entity);
            await _context.SaveChangesAsync();
        }
    }
}
