using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Linq;
using System.Linq.Expressions;
using System.Threading.Tasks;
using Raqeeb.Domain.Interfaces;

namespace Raqeeb.Infrastructure.Persistence
{
    public class InMemoryRepository<T> : IRepository<T> where T : class
    {
        private readonly ConcurrentDictionary<Guid, T> _store = new();

        public Task AddAsync(T entity)
        {
            // Assuming T has an Id property of type Guid. 
            // In a real generic repo, we'd use an interface or reflection.
            // For this demo, we'll use reflection or assume convention.
            var idProp = typeof(T).GetProperty("Id");
            if (idProp != null)
            {
                var id = (Guid)idProp.GetValue(entity)!;
                _store.TryAdd(id, entity);
            }
            return Task.CompletedTask;
        }

        public Task DeleteAsync(T entity)
        {
            var idProp = typeof(T).GetProperty("Id");
            if (idProp != null)
            {
                var id = (Guid)idProp.GetValue(entity)!;
                _store.TryRemove(id, out _);
            }
            return Task.CompletedTask;
        }

        public Task<IEnumerable<T>> FindAsync(Expression<Func<T, bool>> predicate)
        {
            var func = predicate.Compile();
            var results = _store.Values.Where(func);
            return Task.FromResult(results);
        }

        public Task<IEnumerable<T>> GetAllAsync()
        {
            return Task.FromResult((IEnumerable<T>)_store.Values);
        }

        public Task<T?> GetByIdAsync(Guid id)
        {
            _store.TryGetValue(id, out var entity);
            return Task.FromResult(entity);
        }

        public Task UpdateAsync(T entity)
        {
            var idProp = typeof(T).GetProperty("Id");
            if (idProp != null)
            {
                var id = (Guid)idProp.GetValue(entity)!;
                _store[id] = entity;
            }
            return Task.CompletedTask;
        }
    }
}
