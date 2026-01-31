using MediatR;
using Microsoft.AspNetCore.Mvc;
using Raqeeb.Application.Targets.Queries;
using Raqeeb.Domain.Entities;
using Raqeeb.Domain.Interfaces;

namespace Raqeeb.Api.Controllers;

[ApiController]
[Route("api/[controller]")]
public class TargetsController : ControllerBase
{
    private readonly IMediator _mediator;
    private readonly IRepository<Target> _targetRepository;

    public TargetsController(IMediator mediator, IRepository<Target> targetRepository)
    {
        _mediator = mediator;
        _targetRepository = targetRepository;
    }

    [HttpGet]
    public async Task<IActionResult> GetAll()
    {
        var targets = await _mediator.Send(new GetAllTargetsQuery());
        return Ok(targets);
    }

    [HttpGet("{id}")]
    public async Task<IActionResult> GetById(Guid id)
    {
        var target = await _targetRepository.GetByIdAsync(id);
        if (target == null) return NotFound();
        return Ok(target);
    }

    [HttpPost]
    public async Task<IActionResult> Create([FromBody] CreateTargetRequest request)
    {
        var target = new Target
        {
            Url = request.Url,
            OwnerId = request.OwnerId,
            IsVerified = true
        };
        await _targetRepository.AddAsync(target);
        return CreatedAtAction(nameof(GetById), new { id = target.Id }, target);
    }

    [HttpDelete("{id}")]
    public async Task<IActionResult> Delete(Guid id)
    {
        var target = await _targetRepository.GetByIdAsync(id);
        if (target == null) return NotFound();
        await _targetRepository.DeleteAsync(target);
        return NoContent();
    }
}

public record CreateTargetRequest(string Url, Guid? OwnerId);
