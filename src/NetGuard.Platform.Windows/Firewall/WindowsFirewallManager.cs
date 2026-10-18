using System.Management;
using System.Runtime.InteropServices;
using System.Runtime.InteropServices.ComTypes;
using System.ServiceProcess;
using Microsoft.Extensions.Logging;
using NetGuard.Core.Abstractions;
using NetGuard.Core.Firewall;
using NetGuard.Domain;

namespace NetGuard.Platform.Windows.Firewall;

/// <summary>
/// Windows Defender Firewall access through the supported INetFwPolicy2 COM API. Creates only outbound block rules
/// described by <see cref="FirewallRuleSpec"/>, and removes or renames only rules carrying NetGuard's ownership marker.
/// All operations are serialized.
/// </summary>
public sealed class WindowsFirewallManager : IFirewallManager
{
    private static readonly int[] AllowedProtocols = [FirewallProtocols.Any, FirewallProtocols.Tcp, FirewallProtocols.Udp, FirewallProtocols.Icmpv4, FirewallProtocols.Icmpv6];

    private readonly object _gate = new();
    private readonly ILogger<WindowsFirewallManager> _logger;
    private IReadOnlyList<string> _products = [];
    private DateTime _productsReadAt;

    public WindowsFirewallManager(ILogger<WindowsFirewallManager> logger) => _logger = logger;

    public FirewallState GetState()
    {
        lock (_gate)
        {
            var serviceProblem = CheckFirewallService();
            if (serviceProblem is not null)
            {
                return FirewallState.Unavailable(serviceProblem);
            }

            try
            {
                var policy = CreatePolicy();
                try
                {
                    var current = (NetworkProfiles)(policy.get_CurrentProfileTypes() & (int)NetworkProfiles.All);
                    var profiles = new List<FirewallProfileState>();
                    foreach (var profile in new[] { NetworkProfiles.Domain, NetworkProfiles.Private, NetworkProfiles.Public })
                    {
                        profiles.Add(new FirewallProfileState(
                            profile,
                            policy.get_FirewallEnabled((int)profile),
                            policy.get_DefaultOutboundAction((int)profile) == NetFwConstants.ActionBlock,
                            policy.get_DefaultInboundAction((int)profile) == NetFwConstants.ActionBlock));
                    }

                    var modify = policy.get_LocalPolicyModifyState() switch
                    {
                        NetFwConstants.ModifyStateOk => LocalPolicyState.Ok,
                        NetFwConstants.ModifyStateGroupPolicyOverride => LocalPolicyState.GroupPolicyOverride,
                        NetFwConstants.ModifyStateInboundBlocked => LocalPolicyState.InboundBlocked,
                        _ => LocalPolicyState.Unknown,
                    };

                    return new FirewallState
                    {
                        Available = true,
                        CurrentProfiles = current,
                        Profiles = profiles,
                        LocalPolicy = modify,
                        RegisteredProducts = GetRegisteredProducts(),
                    };
                }
                finally
                {
                    Release(policy);
                }
            }
            catch (COMException ex)
            {
                _logger.LogError(ex, "Querying firewall state failed");
                return FirewallState.Unavailable($"Windows Defender Firewall could not be queried (0x{ex.HResult:X8}): {ex.Message}");
            }
            catch (UnauthorizedAccessException ex)
            {
                _logger.LogError(ex, "Access denied querying firewall state");
                return FirewallState.Unavailable("Access to Windows Defender Firewall was denied. The NetGuard service must run as LocalSystem (or elevated when started for diagnostics).");
            }
        }
    }

    public IReadOnlyList<FirewallRule> GetRules()
    {
        lock (_gate)
        {
            var policy = CreatePolicy();
            try
            {
                var result = new List<FirewallRule>();
                foreach (var rule in Enumerate(policy.get_Rules()))
                {
                    try
                    {
                        result.Add(Snapshot(rule));
                    }
                    catch (COMException ex)
                    {
                        _logger.LogDebug(ex, "Skipping unreadable firewall rule");
                    }
                    finally
                    {
                        Release(rule);
                    }
                }

                return result;
            }
            catch (COMException ex)
            {
                throw new FirewallUnavailableException($"Firewall rules could not be read (0x{ex.HResult:X8}): {ex.Message}", ex);
            }
            catch (UnauthorizedAccessException ex)
            {
                throw new FirewallUnavailableException("Access to Windows Defender Firewall rules was denied. The NetGuard service must run as LocalSystem.", ex);
            }
            finally
            {
                Release(policy);
            }
        }
    }

    public void AddRule(FirewallRuleSpec spec)
    {
        Validate(spec);
        lock (_gate)
        {
            var policy = CreatePolicy();
            INetFwRule? rule = null;
            try
            {
                rule = CreateRule();
                rule.put_Name(spec.Name);
                rule.put_Description(spec.Description);
                rule.put_ApplicationName(spec.ApplicationPath);

                // Protocol must be set before ports; ports are only valid for TCP/UDP.
                rule.put_Protocol(spec.Protocol);
                if (spec.Protocol is FirewallProtocols.Tcp or FirewallProtocols.Udp)
                {
                    rule.put_RemotePorts(spec.RemotePorts);
                }

                rule.put_RemoteAddresses(spec.RemoteAddresses);
                rule.put_Direction(NetFwConstants.DirectionOutbound);
                rule.put_Action(NetFwConstants.ActionBlock);
                rule.put_Profiles((int)spec.Profiles);
                rule.put_InterfaceTypes("All");
                rule.put_Grouping(OwnedRules.Grouping);
                rule.put_Enabled(true);
                policy.get_Rules().Add(rule);
                _logger.LogInformation("Created firewall rule {RuleName} for {Path}", spec.Name, spec.ApplicationPath);
            }
            catch (COMException ex)
            {
                throw new FirewallOperationException(Describe(ex, "create the rule"), ex);
            }
            catch (UnauthorizedAccessException ex)
            {
                throw new FirewallOperationException("Access denied while creating the rule. The NetGuard service must run with administrative rights (LocalSystem).", ex);
            }
            finally
            {
                if (rule is not null)
                {
                    Release(rule);
                }

                Release(policy);
            }
        }
    }

    public void RemoveOwnedRule(string name)
    {
        lock (_gate)
        {
            var policy = CreatePolicy();
            try
            {
                var rules = policy.get_Rules();

                // Windows allows duplicate names. Refuse if any rule with this name is not ours, then remove until
                // none remain (Remove deletes one matching rule per call on some Windows versions).
                for (var attempt = 0; attempt < 16; attempt++)
                {
                    var matches = Enumerate(rules)
                        .Select(r =>
                        {
                            try
                            {
                                return string.Equals(r.get_Name(), name, StringComparison.Ordinal) ? Snapshot(r) : null;
                            }
                            finally
                            {
                                Release(r);
                            }
                        })
                        .Where(r => r is not null)
                        .ToList();

                    if (matches.Count == 0)
                    {
                        return;
                    }

                    if (matches.Any(r => !OwnedRules.IsOwned(r!)))
                    {
                        throw new FirewallOperationException($"A rule named '{name}' that was not created by NetGuard exists. NetGuard does not remove rules it does not own.");
                    }

                    rules.Remove(name);
                    _logger.LogInformation("Removed firewall rule {RuleName}", name);
                }

                throw new FirewallOperationException($"Rule '{name}' could not be removed.");
            }
            catch (COMException ex)
            {
                throw new FirewallOperationException(Describe(ex, "remove the rule"), ex);
            }
            finally
            {
                Release(policy);
            }
        }
    }

    public void RenameOwnedRule(string currentName, string newName)
    {
        lock (_gate)
        {
            var policy = CreatePolicy();
            INetFwRule? rule = null;
            try
            {
                rule = policy.get_Rules().Item(currentName);
                if (!OwnedRules.IsOwned(Snapshot(rule)))
                {
                    throw new FirewallOperationException($"Rule '{currentName}' is not owned by NetGuard and was not renamed.");
                }

                rule.put_Name(newName);
            }
            catch (COMException ex)
            {
                throw new FirewallOperationException(Describe(ex, "rename the rule"), ex);
            }
            finally
            {
                if (rule is not null)
                {
                    Release(rule);
                }

                Release(policy);
            }
        }
    }

    /// <summary>Defense in depth: reject anything that is not a well-formed, NetGuard-marked, program-scoped block rule.</summary>
    private static void Validate(FirewallRuleSpec spec)
    {
        if (!OwnedRules.TryParseKey(spec.Key, out _, out _, out _) || OwnedRules.TryGetKey(spec.Description) != spec.Key)
        {
            throw new FirewallOperationException("Refusing to create a rule without a valid NetGuard ownership marker.");
        }

        if (string.IsNullOrWhiteSpace(spec.Name) || spec.Name.Length > 1024)
        {
            throw new FirewallOperationException("Refusing to create a rule without a valid name.");
        }

        if (ExecutablePathRules.ValidateSyntax(spec.ApplicationPath) is { } pathError)
        {
            throw new FirewallOperationException("Refusing to create a rule for an invalid program path: " + pathError);
        }

        if (!AllowedProtocols.Contains(spec.Protocol))
        {
            throw new FirewallOperationException($"Protocol {spec.Protocol} is not supported.");
        }

        if (spec.Profiles == NetworkProfiles.None || (spec.Profiles & ~NetworkProfiles.All) != 0)
        {
            throw new FirewallOperationException("Invalid network profile selection.");
        }

        if (string.IsNullOrWhiteSpace(spec.RemoteAddresses))
        {
            throw new FirewallOperationException("Remote addresses must be specified.");
        }
    }

    private static FirewallRule Snapshot(INetFwRule rule) => new()
    {
        Name = rule.get_Name() ?? string.Empty,
        Description = rule.get_Description(),
        ApplicationName = rule.get_ApplicationName(),
        ServiceName = rule.get_ServiceName(),
        Grouping = rule.get_Grouping(),
        Direction = rule.get_Direction() == NetFwConstants.DirectionInbound ? FirewallDirection.Inbound : FirewallDirection.Outbound,
        Action = rule.get_Action() == NetFwConstants.ActionAllow ? FirewallAction.Allow : FirewallAction.Block,
        Enabled = rule.get_Enabled(),
        Protocol = rule.get_Protocol(),
        RemoteAddresses = rule.get_RemoteAddresses(),
        RemotePorts = rule.get_RemotePorts(),
        LocalAddresses = rule.get_LocalAddresses(),
        LocalPorts = rule.get_LocalPorts(),
        Profiles = rule.get_Profiles(),
        InterfaceTypes = rule.get_InterfaceTypes(),
    };

    private static IEnumerable<INetFwRule> Enumerate(INetFwRules rules)
    {
        var enumerator = (IEnumVARIANT)rules.get__NewEnum();
        try
        {
            var buffer = new object[1];
            while (enumerator.Next(1, buffer, IntPtr.Zero) == 0)
            {
                if (buffer[0] is INetFwRule rule)
                {
                    yield return rule;
                }
                else if (buffer[0] is not null)
                {
                    Marshal.ReleaseComObject(buffer[0]);
                }

                buffer[0] = null!;
            }
        }
        finally
        {
            Marshal.ReleaseComObject(enumerator);
        }
    }

    private static INetFwPolicy2 CreatePolicy()
    {
        var type = Type.GetTypeFromProgID("HNetCfg.FwPolicy2", throwOnError: true)!;
        return (INetFwPolicy2)Activator.CreateInstance(type)!;
    }

    private static INetFwRule CreateRule()
    {
        var type = Type.GetTypeFromProgID("HNetCfg.FWRule", throwOnError: true)!;
        return (INetFwRule)Activator.CreateInstance(type)!;
    }

    private static void Release(object comObject)
    {
        if (Marshal.IsComObject(comObject))
        {
            Marshal.ReleaseComObject(comObject);
        }
    }

    private static string? CheckFirewallService()
    {
        try
        {
            using var service = new ServiceController("mpssvc");
            return service.Status == ServiceControllerStatus.Running
                ? null
                : $"The Windows Defender Firewall service (mpssvc) is {service.Status}. Firewall rules cannot be enforced until it is running.";
        }
        catch (Exception ex) when (ex is InvalidOperationException or System.ComponentModel.Win32Exception)
        {
            // The service status could not be read (for example restricted access to the Service Control Manager).
            // That is not evidence the firewall is down; the COM query that follows decides availability.
            return null;
        }
    }

    private IReadOnlyList<string> GetRegisteredProducts()
    {
        if (DateTime.UtcNow - _productsReadAt < TimeSpan.FromMinutes(10))
        {
            return _products;
        }

        _productsReadAt = DateTime.UtcNow;
        try
        {
            // Windows Security Center lists firewalls registered by third-party security products (client SKUs only).
            using var searcher = new ManagementObjectSearcher(@"root\SecurityCenter2", "SELECT displayName FROM FirewallProduct");
            _products = searcher.Get().Cast<ManagementObject>().Select(o => o["displayName"]?.ToString()).OfType<string>().ToList();
        }
        catch (Exception ex) when (ex is ManagementException or COMException or UnauthorizedAccessException)
        {
            _products = [];
        }

        return _products;
    }

    private static string Describe(COMException ex, string action) => (uint)ex.HResult switch
    {
        0x80070005 => $"Access denied while trying to {action}. The NetGuard service must run as LocalSystem.",
        0x800706D9 or 0x800706BA => $"Could not {action}: the Windows Defender Firewall service is not running.",
        0x80070057 => $"Could not {action}: Windows Firewall rejected a rule property as invalid ({ex.Message}).",
        _ => $"Could not {action} (0x{ex.HResult:X8}): {ex.Message}",
    };
}
