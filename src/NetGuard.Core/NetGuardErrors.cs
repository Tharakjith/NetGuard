using NetGuard.Contracts;

namespace NetGuard.Core;

/// <summary>An expected, user-actionable failure that maps to an IPC error code.</summary>
public class NetGuardException : Exception
{
    public NetGuardException(string code, string message)
        : base(message)
    {
        Code = code;
    }

    public string Code { get; }
}

public sealed class NotFoundException(string message) : NetGuardException(IpcErrorCodes.NotFound, message);

public sealed class AuthorizationException(string message) : NetGuardException(IpcErrorCodes.Unauthorized, message);

public sealed class OrganizationManagedException(string name)
    : NetGuardException(IpcErrorCodes.OrganizationManaged, $"'{name}' is managed by organization policy and cannot be changed here. Update the organization policy file instead.");

public sealed class ConflictException(string message) : NetGuardException(IpcErrorCodes.Conflict, message);
