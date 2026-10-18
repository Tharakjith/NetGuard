using System.Net;
using NetGuard.Domain.Networking;
using Xunit;

namespace NetGuard.Tests.Unit;

public sealed class AddressSetTests
{
    [Theory]
    [InlineData("10.1.2.3")]
    [InlineData("10.0.0.0/8")]
    [InlineData("10.0.0.0/255.0.0.0")]
    [InlineData("10.0.0.1-10.0.0.9")]
    [InlineData("2001:db8::/32")]
    [InlineData("2001:db8::1-2001:db8::ff")]
    [InlineData("::1")]
    public void Parses_FirewallAddressForms(string entry)
    {
        Assert.True(AddressSet.TryParse([entry], out var set, out var error), error);
        Assert.False(set.IsEmpty);
    }

    [Theory]
    [InlineData("LocalSubnet")]
    [InlineData("10")]
    [InlineData("1.2")]
    [InlineData("fe80::1%12")]
    [InlineData("10.0.0.0/33")]
    [InlineData("10.0.0.0/255.0.255.0")]
    [InlineData("10.0.0.9-10.0.0.1")]
    [InlineData("10.0.0.1-::1")]
    [InlineData("example.com")]
    public void Rejects_InvalidOrUncomplementableEntries(string entry)
    {
        Assert.False(AddressSet.TryParse([entry], out _, out var error));
        Assert.False(string.IsNullOrEmpty(error));
    }

    [Fact]
    public void CidrAndMaskForms_AreSemanticallyEqual()
    {
        var cidr = AddressSet.Parse(["192.168.0.0/16"]);
        Assert.True(AddressSet.TryParseFirewallString("192.168.0.0/255.255.0.0", out var mask, out _));
        Assert.True(AddressSet.TryParseFirewallString("192.168.0.0-192.168.255.255", out var range, out _));
        Assert.Equal(cidr, mask);
        Assert.Equal(cidr, range);
    }

    [Fact]
    public void Complement_CoversEverythingElse_InBothFamilies()
    {
        var allowed = AddressSet.Parse(["140.82.112.0/20"]);
        var blocked = allowed.Complement();

        Assert.False(blocked.Contains(IPAddress.Parse("140.82.112.5")));
        Assert.True(blocked.Contains(IPAddress.Parse("140.82.111.255")));
        Assert.True(blocked.Contains(IPAddress.Parse("8.8.8.8")));
        Assert.True(blocked.Contains(IPAddress.Parse("2606:4700::1111")), "IPv6 must be blocked when only IPv4 is allowed.");
        Assert.True(blocked.Complement().Equals(allowed));
        Assert.Equal("0.0.0.0-140.82.111.255,140.82.128.0-255.255.255.255,::-ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff", blocked.ToFirewallString());
    }

    [Fact]
    public void Complement_HandlesEdgesOfAddressSpace()
    {
        var edges = AddressSet.Parse(["0.0.0.0", "255.255.255.255", "::", "ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff"]);
        var complement = edges.Complement();
        Assert.False(complement.Contains(IPAddress.Parse("0.0.0.0")));
        Assert.False(complement.Contains(IPAddress.Parse("255.255.255.255")));
        Assert.True(complement.Contains(IPAddress.Parse("1.0.0.0")));
        Assert.True(AddressSet.Any.Complement().IsEmpty);
        Assert.True(AddressSet.Empty.Complement().IsAny);
    }

    [Fact]
    public void FirewallString_RoundTrips()
    {
        var set = AddressSet.Parse(["10.0.0.0/8", "10.1.0.0/16", "192.168.1.1", "2001:db8::/48"]);
        Assert.True(AddressSet.TryParseFirewallString(set.ToFirewallString(), out var parsed, out _));
        Assert.Equal(set, parsed);
        Assert.Equal(3, set.EntryCount); // 10.1/16 merges into 10/8
    }

    [Fact]
    public void LocalNetwork_IncludesPrivateRangesOnly()
    {
        Assert.True(AddressSet.LocalNetwork.Contains(IPAddress.Parse("192.168.1.10")));
        Assert.True(AddressSet.LocalNetwork.Contains(IPAddress.Parse("fe80::1")));
        Assert.False(AddressSet.LocalNetwork.Contains(IPAddress.Parse("8.8.8.8")));
        Assert.False(AddressSet.LocalNetwork.Contains(IPAddress.Parse("100.64.0.1")));
    }
}

public sealed class PortSetTests
{
    [Fact]
    public void ParsesListsRangesAndSpecialValues()
    {
        Assert.True(PortSet.Parse("*").IsAll);
        Assert.True(PortSet.Parse("").IsEmpty);
        var set = PortSet.Parse("443, 80,8000-8100");
        Assert.True(set.Contains(80) && set.Contains(8050) && !set.Contains(8101));
        Assert.Equal("80,443,8000-8100", set.ToString());
    }

    [Theory]
    [InlineData("0")]
    [InlineData("65536")]
    [InlineData("100-50")]
    [InlineData("http")]
    [InlineData("-5")]
    public void RejectsInvalidPorts(string text) => Assert.False(PortSet.TryParse(text, out _, out _));

    [Fact]
    public void Complement_IsWithinValidPortRange()
    {
        Assert.Equal("1-442,444-65535", PortSet.Parse("443").Complement().ToFirewallString());
        Assert.Equal("2-65534", PortSet.Parse("1,65535").Complement().ToFirewallString());
        Assert.True(PortSet.All.Complement().IsEmpty);
    }
}
