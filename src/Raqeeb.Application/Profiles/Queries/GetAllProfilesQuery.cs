using MediatR;
using Raqeeb.Domain.Entities;
using Raqeeb.Domain.Interfaces;

namespace Raqeeb.Application.Profiles.Queries;

public record GetAllProfilesQuery : IRequest<IEnumerable<ScanProfileDto>>;

public record ScanProfileDto(
    Guid Id,
    string Name,
    string Description,
    List<string> EnabledModules,
    int RequestTimeoutSeconds,
    int MaxConcurrency);

public class GetAllProfilesQueryHandler : IRequestHandler<GetAllProfilesQuery, IEnumerable<ScanProfileDto>>
{
    private readonly IRepository<ScanProfile> _profileRepository;

    public GetAllProfilesQueryHandler(IRepository<ScanProfile> profileRepository)
    {
        _profileRepository = profileRepository;
    }

    public async Task<IEnumerable<ScanProfileDto>> Handle(GetAllProfilesQuery request, CancellationToken cancellationToken)
    {
        var profiles = await _profileRepository.GetAllAsync();
        return profiles.Select(p => new ScanProfileDto(
            p.Id,
            p.Name,
            p.Description,
            p.EnabledModules,
            p.RequestTimeoutSeconds,
            p.MaxConcurrency));
    }
}
