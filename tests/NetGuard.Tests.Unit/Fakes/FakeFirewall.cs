using NetGuard.Core.Abstractions;
using NetGuard.Core.Firewall;
using NetGuard.Domain;

namespace NetGuard.Tests.Unit.Fakes;

/// <summary>
/// In-memory firewall with the same ownership guarantees as the real implementation. Records a snapshot after every
/// mutation so tests can assert properties that must hold at every intermediate step.
/// </summary>
public sealed class FakeFirewall : IFirewallManager
{
    private readonly object _gate = new();
    private readonly List<FirewallRule> _rules = [];

    public FirewallState State { get; set; } = new()
    {
        Available = true,
        CurrentProfiles = NetworkProfiles.Private,
        LocalPolicy = LocalPolicyState.Ok,
        Profiles =
        [
            new FirewallProfileState(NetworkProfiles.Domain, true, false, true),
            new FirewallProfileState(NetworkProfiles.Private, true, false, true),
            new FirewallProfileState(NetworkProfiles.Public, true, false, true),
        ],
    };

    /// <summary>Snapshots of the rule set after each mutation.</summary>
    public List<IReadOnlyList<FirewallRule>> History { get; } = [];

    public int MutationCount { get; private set; }

    /// <summary>When set, AddRule throws for specs matching the predicate.</summary>
    public Func<FirewallRuleSpec, bool>? FailAdd { get; set; }

    public bool FailRemove { get; set; }

    public bool Unavailable { get; set; }

    public IReadOnlyList<FirewallRule> Rules
    {
        get
        {
            lock (_gate)
            {
                return _rules.ToList();
            }
        }
    }

    public FirewallState GetState() => Unavailable ? FirewallState.Unavailable("Windows Defender Firewall service is stopped.") : State;

    public IReadOnlyList<FirewallRule> GetRules()
    {
        if (Unavailable)
        {
            throw new FirewallUnavailableException("Windows Defender Firewall service is stopped.");
        }

        return Rules;
    }

    public void AddRule(FirewallRuleSpec spec)
    {
        if (FailAdd?.Invoke(spec) == true)
        {
            throw new FirewallOperationException("Simulated failure creating the rule.");
        }

        Mutate(() => _rules.Add(new FirewallRule
        {
            Name = spec.Name,
            Description = spec.Description,
            ApplicationName = spec.ApplicationPath,
            Grouping = OwnedRules.Grouping,
            Direction = FirewallDirection.Outbound,
            Action = FirewallAction.Block,
            Enabled = true,
            Protocol = spec.Protocol,
            RemoteAddresses = spec.RemoteAddresses,
            RemotePorts = spec.Protocol is FirewallProtocols.Tcp or FirewallProtocols.Udp ? spec.RemotePorts : "*",
            LocalAddresses = "*",
            LocalPorts = "*",
            Profiles = (int)spec.Profiles,
            InterfaceTypes = "All",
        }));
    }

    public void RemoveOwnedRule(string name)
    {
        if (FailRemove)
        {
            throw new FirewallOperationException("Simulated failure removing the rule.");
        }

        Mutate(() =>
        {
            var matches = _rules.Where(r => r.Name == name).ToList();
            if (matches.Any(r => !OwnedRules.IsOwned(r)))
            {
                throw new FirewallOperationException($"A rule named '{name}' is not owned by NetGuard.");
            }

            _rules.RemoveAll(r => r.Name == name);
        });
    }

    public void RenameOwnedRule(string currentName, string newName) => Mutate(() =>
    {
        var index = _rules.FindIndex(r => r.Name == currentName);
        if (index < 0 || !OwnedRules.IsOwned(_rules[index]))
        {
            throw new FirewallOperationException("Not owned.");
        }

        _rules[index] = _rules[index] with { Name = newName };
    });

    /// <summary>Simulates a change made outside NetGuard (another tool or an administrator).</summary>
    public void External(Action<List<FirewallRule>> change)
    {
        lock (_gate)
        {
            change(_rules);
        }
    }

    private void Mutate(Action action)
    {
        lock (_gate)
        {
            action();
            MutationCount++;
            History.Add(_rules.ToList());
        }
    }

    public static FirewallRule ThirdPartyRule(string name, string path, FirewallAction action = FirewallAction.Block) => new()
    {
        Name = name,
        Description = "Created by someone else",
        ApplicationName = path,
        Grouping = "Contoso Security",
        Direction = FirewallDirection.Outbound,
        Action = action,
        Enabled = true,
        Protocol = FirewallProtocols.Any,
        RemoteAddresses = "*",
        Profiles = 0x7FFFFFFF,
    };
}
