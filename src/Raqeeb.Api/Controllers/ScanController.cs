using System;
using System.Threading.Tasks;
using MediatR;
using Microsoft.AspNetCore.Mvc;
using Raqeeb.Application.Scans.Commands;
using Raqeeb.Application.Scans.Queries;

namespace Raqeeb.Api.Controllers
{
    [ApiController]
    [Route("api/[controller]")]
    public class ScanController : ControllerBase
    {
        private readonly IMediator _mediator;

        public ScanController(IMediator mediator)
        {
            _mediator = mediator;
        }

        [HttpPost]
        public async Task<IActionResult> CreateScan([FromBody] CreateScanCommand command)
        {
            var scanId = await _mediator.Send(command);
            return AcceptedAtAction(nameof(GetScanStatus), new { id = scanId }, new { id = scanId });
        }

        [HttpGet("{id}")]
        public async Task<IActionResult> GetScanStatus(Guid id)
        {
            var status = await _mediator.Send(new GetScanStatusQuery { ScanJobId = id });
            if (status == null) return NotFound();
            return Ok(status);
        }
    }
}
