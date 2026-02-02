using Xunit;
using FluentAssertions;

namespace Raqeeb.Tests.Scanning;

public class SimpleTest
{
    [Fact]
    public void Test_Should_Pass()
    {
        true.Should().BeTrue();
    }
}
