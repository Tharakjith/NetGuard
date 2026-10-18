using System.Runtime.InteropServices;

namespace NetGuard.Platform.Windows.Firewall;

// Typed declarations of the Windows Firewall with Advanced Security COM API (netfw.h / FirewallAPI.dll).
// Methods are declared in exact vtable order. Methods NetGuard must never call (disabling the firewall, changing
// default actions, restoring defaults, enabling rule groups) are declared only as unnamed placeholder slots, so no
// code path in this product can invoke them.

#pragma warning disable SA1300, IDE1006 // COM names

internal static class NetFwConstants
{
    public const int DirectionInbound = 1;
    public const int DirectionOutbound = 2;
    public const int ActionBlock = 0;
    public const int ActionAllow = 1;
    public const int ProfileDomain = 1;
    public const int ProfilePrivate = 2;
    public const int ProfilePublic = 4;
    public const int ModifyStateOk = 0;
    public const int ModifyStateGroupPolicyOverride = 1;
    public const int ModifyStateInboundBlocked = 2;
}

[ComImport]
[Guid("98325047-C671-4174-8D81-DEFCD3F03186")]
[InterfaceType(ComInterfaceType.InterfaceIsDual)]
internal interface INetFwPolicy2
{
    [DispId(1)]
    int get_CurrentProfileTypes();

    [DispId(2)]
    [return: MarshalAs(UnmanagedType.VariantBool)]
    bool get_FirewallEnabled(int profileType);

    void _slot_put_FirewallEnabled();

    void _slot_get_ExcludedInterfaces();

    void _slot_put_ExcludedInterfaces();

    [DispId(4)]
    [return: MarshalAs(UnmanagedType.VariantBool)]
    bool get_BlockAllInboundTraffic(int profileType);

    void _slot_put_BlockAllInboundTraffic();

    void _slot_get_NotificationsDisabled();

    void _slot_put_NotificationsDisabled();

    void _slot_get_UnicastResponsesToMulticastBroadcastDisabled();

    void _slot_put_UnicastResponsesToMulticastBroadcastDisabled();

    [DispId(7)]
    INetFwRules get_Rules();

    void _slot_get_ServiceRestriction();

    void _slot_EnableRuleGroup();

    void _slot_IsRuleGroupEnabled();

    void _slot_RestoreLocalFirewallDefaults();

    [DispId(12)]
    int get_DefaultInboundAction(int profileType);

    void _slot_put_DefaultInboundAction();

    [DispId(13)]
    int get_DefaultOutboundAction(int profileType);

    void _slot_put_DefaultOutboundAction();

    void _slot_get_IsRuleGroupCurrentlyEnabled();

    [DispId(15)]
    int get_LocalPolicyModifyState();
}

[ComImport]
[Guid("9C4C6277-5027-441E-AFAE-CA1F542DA009")]
[InterfaceType(ComInterfaceType.InterfaceIsDual)]
internal interface INetFwRules
{
    [DispId(1)]
    int get_Count();

    [DispId(2)]
    void Add([MarshalAs(UnmanagedType.Interface)] INetFwRule rule);

    [DispId(3)]
    void Remove([MarshalAs(UnmanagedType.BStr)] string name);

    [DispId(4)]
    INetFwRule Item([MarshalAs(UnmanagedType.BStr)] string name);

    [DispId(-4)]
    [return: MarshalAs(UnmanagedType.IUnknown)]
    object get__NewEnum();
}

[ComImport]
[Guid("AF230D27-BABA-4E42-ACED-F524F22CFCE2")]
[InterfaceType(ComInterfaceType.InterfaceIsDual)]
internal interface INetFwRule
{
    [DispId(1)]
    [return: MarshalAs(UnmanagedType.BStr)]
    string get_Name();

    [DispId(1)]
    void put_Name([MarshalAs(UnmanagedType.BStr)] string value);

    [DispId(2)]
    [return: MarshalAs(UnmanagedType.BStr)]
    string get_Description();

    [DispId(2)]
    void put_Description([MarshalAs(UnmanagedType.BStr)] string value);

    [DispId(3)]
    [return: MarshalAs(UnmanagedType.BStr)]
    string get_ApplicationName();

    [DispId(3)]
    void put_ApplicationName([MarshalAs(UnmanagedType.BStr)] string value);

    [DispId(4)]
    [return: MarshalAs(UnmanagedType.BStr)]
    string get_ServiceName();

    [DispId(4)]
    void put_ServiceName([MarshalAs(UnmanagedType.BStr)] string value);

    [DispId(5)]
    int get_Protocol();

    [DispId(5)]
    void put_Protocol(int value);

    [DispId(6)]
    [return: MarshalAs(UnmanagedType.BStr)]
    string get_LocalPorts();

    [DispId(6)]
    void put_LocalPorts([MarshalAs(UnmanagedType.BStr)] string value);

    [DispId(7)]
    [return: MarshalAs(UnmanagedType.BStr)]
    string get_RemotePorts();

    [DispId(7)]
    void put_RemotePorts([MarshalAs(UnmanagedType.BStr)] string value);

    [DispId(8)]
    [return: MarshalAs(UnmanagedType.BStr)]
    string get_LocalAddresses();

    [DispId(8)]
    void put_LocalAddresses([MarshalAs(UnmanagedType.BStr)] string value);

    [DispId(9)]
    [return: MarshalAs(UnmanagedType.BStr)]
    string get_RemoteAddresses();

    [DispId(9)]
    void put_RemoteAddresses([MarshalAs(UnmanagedType.BStr)] string value);

    [DispId(10)]
    [return: MarshalAs(UnmanagedType.BStr)]
    string get_IcmpTypesAndCodes();

    [DispId(10)]
    void put_IcmpTypesAndCodes([MarshalAs(UnmanagedType.BStr)] string value);

    [DispId(11)]
    int get_Direction();

    [DispId(11)]
    void put_Direction(int value);

    [DispId(12)]
    object get_Interfaces();

    [DispId(12)]
    void put_Interfaces(object value);

    [DispId(13)]
    [return: MarshalAs(UnmanagedType.BStr)]
    string get_InterfaceTypes();

    [DispId(13)]
    void put_InterfaceTypes([MarshalAs(UnmanagedType.BStr)] string value);

    [DispId(14)]
    [return: MarshalAs(UnmanagedType.VariantBool)]
    bool get_Enabled();

    [DispId(14)]
    void put_Enabled([MarshalAs(UnmanagedType.VariantBool)] bool value);

    [DispId(15)]
    [return: MarshalAs(UnmanagedType.BStr)]
    string get_Grouping();

    [DispId(15)]
    void put_Grouping([MarshalAs(UnmanagedType.BStr)] string value);

    [DispId(16)]
    int get_Profiles();

    [DispId(16)]
    void put_Profiles(int value);

    [DispId(17)]
    [return: MarshalAs(UnmanagedType.VariantBool)]
    bool get_EdgeTraversal();

    [DispId(17)]
    void put_EdgeTraversal([MarshalAs(UnmanagedType.VariantBool)] bool value);

    [DispId(18)]
    int get_Action();

    [DispId(18)]
    void put_Action(int value);
}
