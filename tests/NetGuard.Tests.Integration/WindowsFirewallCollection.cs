using Xunit;

namespace NetGuard.Tests.Integration;

/// <summary>
/// Tests that read or change the real Windows Firewall share this collection so they never run in parallel:
/// a test that counts rules must not observe rules another test is creating at the same moment.
/// </summary>
[CollectionDefinition(Name, DisableParallelization = true)]
public sealed class WindowsFirewallCollection
{
    public const string Name = "Windows Firewall";
}
