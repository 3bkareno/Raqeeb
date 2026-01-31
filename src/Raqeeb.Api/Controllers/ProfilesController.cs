using MediatR;
using Microsoft.AspNetCore.Mvc;
using Raqeeb.Application.Profiles.Queries;
using Raqeeb.Domain.Entities;
using Raqeeb.Domain.Interfaces;

namespace Raqeeb.Api.Controllers;

[ApiController]
[Route("api/[controller]")]
public class ProfilesController : ControllerBase
{
    private readonly IMediator _mediator;
    private readonly IRepository<ScanProfile> _profileRepository;

    public ProfilesController(IMediator mediator, IRepository<ScanProfile> profileRepository)
    {
        _mediator = mediator;
        _profileRepository = profileRepository;
    }

    [HttpGet]
    public async Task<IActionResult> GetAll()
    {
        var profiles = await _mediator.Send(new GetAllProfilesQuery());
        return Ok(profiles);
    }

    [HttpGet("{id}")]
    public async Task<IActionResult> GetById(Guid id)
    {
        var profile = await _profileRepository.GetByIdAsync(id);
        if (profile == null) return NotFound();
        return Ok(profile);
    }

    [HttpPost]
    public async Task<IActionResult> Create([FromBody] CreateProfileRequest request)
    {
        var profile = new ScanProfile
        {
            Name = request.Name,
            Description = request.Description,
            EnabledModules = request.EnabledModules,
            RequestTimeoutSeconds = request.RequestTimeoutSeconds,
            MaxConcurrency = request.MaxConcurrency
        };
        await _profileRepository.AddAsync(profile);
        return CreatedAtAction(nameof(GetById), new { id = profile.Id }, profile);
    }

    [HttpPut("{id}")]
    public async Task<IActionResult> Update(Guid id, [FromBody] UpdateProfileRequest request)
    {
        var profile = await _profileRepository.GetByIdAsync(id);
        if (profile == null) return NotFound();

        profile.Name = request.Name;
        profile.Description = request.Description;
        profile.EnabledModules = request.EnabledModules;
        profile.RequestTimeoutSeconds = request.RequestTimeoutSeconds;
        profile.MaxConcurrency = request.MaxConcurrency;

        await _profileRepository.UpdateAsync(profile);
        return Ok(profile);
    }

    [HttpDelete("{id}")]
    public async Task<IActionResult> Delete(Guid id)
    {
        var profile = await _profileRepository.GetByIdAsync(id);
        if (profile == null) return NotFound();
        await _profileRepository.DeleteAsync(profile);
        return NoContent();
    }
}

public record CreateProfileRequest(
    string Name, 
    string Description, 
    List<string> EnabledModules, 
    int RequestTimeoutSeconds, 
    int MaxConcurrency);

public record UpdateProfileRequest(
    string Name, 
    string Description, 
    List<string> EnabledModules, 
    int RequestTimeoutSeconds, 
    int MaxConcurrency);
