using System.Buffers.Binary;

namespace Company.ExchangeMcp.Exchange;

/// <summary>
/// Evaluates only the two directory rights that the mailbox permission reader needs.
/// It deliberately returns unknown for structures it cannot prove safe to interpret.
/// </summary>
public static class DirectoryAclEvaluator
{
    private const ushort SecurityDescriptorSelfRelative = 0x8000;
    private const ushort SecurityDescriptorDaclPresent = 0x0004;
    private const ushort SecurityDescriptorSaclPresent = 0x0010;
    private const byte AccessAllowedAce = 0;
    private const byte AccessDeniedAce = 1;
    private const byte AccessAllowedObjectAce = 5;
    private const byte AccessDeniedObjectAce = 6;
    private const uint AceObjectTypePresent = 0x00000001;
    private const uint AceInheritedObjectTypePresent = 0x00000002;
    private const byte AceInherited = 0x10;
    private const byte AceInheritOnly = 0x08;
    private const byte SupportedAccessAceFlags = 0x1F;
    private const uint FullAccess = 0x00000001;
    private const uint DsControlAccess = 0x00000100;
    private const uint GenericAccessMask = 0xF0000000;
    private const int MaximumDescriptorBytes = 65536;
    private const int MaximumAces = 2048;
    private const int MaximumSidBytes = 68;
    private const string EveryoneSid = "010100000000000100000000";
    private const string AuthenticatedUsersSid = "01010000000000050B000000";
    private const string SendAsRightGuid = "ab721a541e2f11d0981900aa0040529b";

    public static string SidKey(byte[] value)
    {
        ArgumentNullException.ThrowIfNull(value);
        if (!TryReadSid(value, 0, value.Length, out var length) || length != value.Length)
            throw new FormatException("The value is not one complete Windows SID.");

        return Convert.ToHexString(value);
    }

    public static PermissionDecision Evaluate(
        byte[]? descriptor,
        string actorSid,
        IReadOnlySet<string> actorSids,
        bool groupsComplete,
        bool sendAs) => EvaluateCore(descriptor, actorSid, actorSids, groupsComplete,
            sendAs ? DsControlAccess : FullAccess, sendAs ? SendAsRightGuid : null, null, sendAs);

    public static PermissionDecision EvaluatePropertyRead(byte[]? descriptor, string actorSid,
        IReadOnlySet<string> actorSids, bool groupsComplete, Guid attributeId, Guid propertySetId) =>
        EvaluateCore(descriptor, actorSid, actorSids, groupsComplete, 0x10,
            attributeId.ToString("N"), propertySetId.ToString("N"), true);

    private static PermissionDecision EvaluateCore(byte[]? descriptor, string actorSid,
        IReadOnlySet<string> actorSids, bool groupsComplete, uint requiredMask, string? rightGuid,
        string? propertySetGuid, bool directoryRight)
    {
        if (descriptor is null || descriptor.Length == 0)
            return PermissionDecision.Unknown("permission descriptor is missing");
        if (descriptor.Length > MaximumDescriptorBytes)
            return PermissionDecision.Unknown("permission descriptor is too large");
        if (!TrySidKey(actorSid, out var actorKey))
            return PermissionDecision.Unknown("actor SID is invalid");

        var principals = new HashSet<string>(StringComparer.Ordinal)
        {
            actorKey
        };
        if (actorSids is null)
            return PermissionDecision.Unknown("directory groups are unavailable");
        foreach (var sid in actorSids)
        {
            if (!TrySidKey(sid, out var key))
                return PermissionDecision.Unknown("directory groups are unreadable");
            principals.Add(key);
        }

        if (!TryReadDescriptor(descriptor, out var dacl, out var parseReason))
            return PermissionDecision.Unknown(parseReason);

        foreach (var ace in dacl)
        {
            if (!IsPrincipalMatch(ace.SidKey, actorKey, principals, out var direct, out var viaGroup))
                continue;
            if ((ace.Flags & AceInheritOnly) != 0)
                continue;
            if (!directoryRight && (ace.Mask & GenericAccessMask) != 0)
                return PermissionDecision.Unknown("permission ACE uses an unsupported generic access right");

            var effectiveAce = directoryRight ? ace with { Mask = MapDirectoryGenericRights(ace.Mask) } : ace;
            var rightApplies = AppliesToRight(effectiveAce, requiredMask, rightGuid, propertySetGuid, out var ambiguous);
            if (ambiguous)
                return PermissionDecision.Unknown("permission ACE has an ambiguous inherited object scope");
            if (!rightApplies)
                continue;

            var inherited = (ace.Flags & AceInherited) != 0;
            if (ace.Deny)
            {
                return new PermissionDecision(
                    "denied",
                    "matching deny ACE blocked the requested right",
                    direct,
                    viaGroup,
                    inherited,
                    MatchingDeny: true);
            }

            if (!groupsComplete)
                return PermissionDecision.Unknown("directory groups are incomplete");

            return new PermissionDecision(
                "allowed",
                "matching allow ACE granted the requested right",
                direct,
                viaGroup,
                inherited);
        }

        return groupsComplete
            ? new PermissionDecision("denied", "no matching allow ACE granted the requested right")
            : PermissionDecision.Unknown("directory groups are incomplete");
    }

    private static bool AppliesToRight(
        ParsedAce ace,
        uint requiredMask,
        string? rightGuid,
        string? propertySetGuid,
        out bool ambiguous)
    {
        ambiguous = false;
        if ((ace.Mask & requiredMask) == 0)
            return false;
        if (!ace.ObjectAce)
            return true;

        if (!ace.ObjectTypePresent)
            return true;
        if (rightGuid is null)
        {
            // The evaluator has no target object class GUID for FullAccess.
            ambiguous = true;
            return false;
        }

        // InheritedObjectType filters propagation to children; inherit-only ACEs were already skipped.
        return string.Equals(ace.ObjectTypeKey, rightGuid, StringComparison.OrdinalIgnoreCase)
            || propertySetGuid is not null && string.Equals(ace.ObjectTypeKey, propertySetGuid, StringComparison.OrdinalIgnoreCase);
    }

    private static uint MapDirectoryGenericRights(uint mask)
    {
        // MS-ADTS 5.1.3.2; mailbox-store generic rights intentionally use the separate conservative path.
        var result = mask & ~GenericAccessMask;
        if ((mask & 0x80000000) != 0) result |= 0x00020094;
        if ((mask & 0x40000000) != 0) result |= 0x00020028;
        if ((mask & 0x20000000) != 0) result |= 0x00020004;
        if ((mask & 0x10000000) != 0) result |= 0x000F01FF;
        return result;
    }

    private static bool IsPrincipalMatch(
        string sidKey,
        string actorKey,
        HashSet<string> principals,
        out bool direct,
        out bool viaGroup)
    {
        direct = string.Equals(sidKey, actorKey, StringComparison.Ordinal);
        if (direct)
        {
            viaGroup = false;
            return true;
        }

        viaGroup = principals.Contains(sidKey)
            || string.Equals(sidKey, EveryoneSid, StringComparison.Ordinal)
            || string.Equals(sidKey, AuthenticatedUsersSid, StringComparison.Ordinal);
        return viaGroup;
    }

    private static bool TryReadDescriptor(byte[] value, out List<ParsedAce> dacl, out string reason)
    {
        dacl = [];
        reason = "permission descriptor is malformed";
        if (value.Length < 20 || value[0] != 1 || value[1] != 0)
            return false;

        var control = BinaryPrimitives.ReadUInt16LittleEndian(value.AsSpan(2, 2));
        if ((control & SecurityDescriptorSelfRelative) == 0)
            return false;

        if (!TryReadOffset(value, 4, out var ownerOffset)
            || !TryReadOffset(value, 8, out var groupOffset)
            || !TryReadOffset(value, 12, out var saclOffset)
            || !TryReadOffset(value, 16, out var daclOffset))
            return false;

        if (!AlignedRelativeOffset(ownerOffset)
            || !AlignedRelativeOffset(groupOffset)
            || !AlignedRelativeOffset(saclOffset)
            || !AlignedRelativeOffset(daclOffset))
            return false;

        var segments = new List<DescriptorSegment>(4);
        if (ownerOffset != 0)
        {
            if (ownerOffset < 20 || !TryReadSid(value, ownerOffset, value.Length, out var ownerLength))
                return false;
            segments.Add(new(ownerOffset, ownerOffset + ownerLength, DescriptorSegmentKind.OwnerOrGroup));
        }
        if (groupOffset != 0)
        {
            if (groupOffset < 20 || !TryReadSid(value, groupOffset, value.Length, out var groupLength))
                return false;
            segments.Add(new(groupOffset, groupOffset + groupLength, DescriptorSegmentKind.OwnerOrGroup));
        }

        if ((control & SecurityDescriptorSaclPresent) == 0)
        {
            if (saclOffset != 0)
                return false;
        }
        else if (saclOffset != 0)
        {
            if (saclOffset < 20)
                return false;
            if (!TryReadAcl(value, saclOffset, value.Length, parseAccessAces: false, out _, out _, out var saclEnd))
                return false;
            segments.Add(new(saclOffset, saclEnd, DescriptorSegmentKind.Acl));
        }

        if ((control & SecurityDescriptorDaclPresent) == 0)
        {
            reason = "permission descriptor has no DACL";
            return false;
        }
        if (daclOffset == 0)
        {
            reason = "permission descriptor has a null DACL";
            return false;
        }
        if (daclOffset < 20)
            return false;
        if (!TryReadAcl(value, daclOffset, value.Length, parseAccessAces: true, out dacl, out reason, out var daclEnd))
            return false;

        segments.Add(new(daclOffset, daclEnd, DescriptorSegmentKind.Acl));
        for (var i = 0; i < segments.Count; i++)
        {
            for (var j = i + 1; j < segments.Count; j++)
            {
                var left = segments[i];
                var right = segments[j];
                if (!Overlaps(left, right))
                    continue;
                if (left.Kind == DescriptorSegmentKind.OwnerOrGroup
                    && right.Kind == DescriptorSegmentKind.OwnerOrGroup
                    && left.Start == right.Start
                    && left.End == right.End)
                    continue;
                return false;
            }
        }

        return true;
    }

    private static bool AlignedRelativeOffset(int offset) => offset == 0 || (offset & 3) == 0;

    private static bool Overlaps(DescriptorSegment left, DescriptorSegment right) =>
        left.Start < right.End && right.Start < left.End;

    private static bool TryReadAcl(
        byte[] value,
        int offset,
        int limit,
        bool parseAccessAces,
        out List<ParsedAce> aces,
        out string reason,
        out int end)
    {
        aces = [];
        reason = "permission ACL is malformed";
        end = 0;
        if (offset < 0 || offset > limit - 8)
            return false;

        if (value[offset] is not (2 or 4)
            || value[offset + 1] != 0
            || BinaryPrimitives.ReadUInt16LittleEndian(value.AsSpan(offset + 6, 2)) != 0)
            return false;
        var aclSize = BinaryPrimitives.ReadUInt16LittleEndian(value.AsSpan(offset + 2, 2));
        var aceCount = BinaryPrimitives.ReadUInt16LittleEndian(value.AsSpan(offset + 4, 2));
        if (aclSize < 8 || (aclSize & 3) != 0 || offset > limit - aclSize || aceCount > MaximumAces)
            return false;
        end = offset + aclSize;
        if (!parseAccessAces)
        {
            var cursor = offset + 8;
            for (var i = 0; i < aceCount; i++)
            {
                if (!TryReadAceHeader(value, cursor, end, out var aceSize))
                    return false;
                cursor += aceSize;
            }
            return cursor == end;
        }

        var accessCursor = offset + 8;
        var accessEnd = end;
        for (var i = 0; i < aceCount; i++)
        {
            if (!TryReadAccessAce(value, accessCursor, accessEnd, out var ace, out reason))
                return false;
            aces.Add(ace);
            accessCursor += ace.Size;
        }

        if (accessCursor != accessEnd)
        {
            reason = "permission ACL has trailing bytes";
            return false;
        }
        return true;
    }

    private static bool TryReadAccessAce(
        byte[] value,
        int offset,
        int limit,
        out ParsedAce ace,
        out string reason)
    {
        ace = default;
        reason = "permission ACL contains an unsupported ACE";
        if (!TryReadAceHeader(value, offset, limit, out var size))
        {
            reason = "permission ACL contains a malformed ACE";
            return false;
        }

        var type = value[offset];
        var flags = value[offset + 1];
        if ((flags & ~SupportedAccessAceFlags) != 0)
        {
            reason = "permission ACE has unsupported flags";
            return false;
        }
        var end = offset + size;
        var objectAce = type is AccessAllowedObjectAce or AccessDeniedObjectAce;
        var allowAce = type is AccessAllowedAce or AccessAllowedObjectAce;
        var denyAce = type is AccessDeniedAce or AccessDeniedObjectAce;
        if (!allowAce && !denyAce)
            return false;
        if ((!objectAce && size < 8) || (objectAce && size < 12))
        {
            reason = "permission ACE is too short";
            return false;
        }
        var mask = BinaryPrimitives.ReadUInt32LittleEndian(value.AsSpan(offset + 4, 4));

        var sidOffset = offset + 8;
        var objectTypePresent = false;
        var inheritedObjectTypePresent = false;
        string? objectTypeKey = null;
        if (objectAce)
        {
            var objectFlags = BinaryPrimitives.ReadUInt32LittleEndian(value.AsSpan(offset + 8, 4));
            if ((objectFlags & ~(AceObjectTypePresent | AceInheritedObjectTypePresent)) != 0)
            {
                reason = "permission object ACE has unsupported flags";
                return false;
            }
            sidOffset = offset + 12;
            objectTypePresent = (objectFlags & AceObjectTypePresent) != 0;
            inheritedObjectTypePresent = (objectFlags & AceInheritedObjectTypePresent) != 0;
            if (objectTypePresent)
            {
                if (sidOffset > end - 16)
                {
                    reason = "permission object ACE has a truncated object GUID";
                    return false;
                }
                objectTypeKey = new Guid(value.AsSpan(sidOffset, 16)).ToString("N");
                sidOffset += 16;
            }
            if (inheritedObjectTypePresent)
            {
                if (sidOffset > end - 16)
                {
                    reason = "permission object ACE has a truncated inherited object GUID";
                    return false;
                }
                sidOffset += 16;
            }
        }

        if (!TryReadSid(value, sidOffset, end, out var sidLength) || sidOffset + sidLength != end)
        {
            reason = "permission ACE has an invalid SID or trailing data";
            return false;
        }

        ace = new ParsedAce(
            size,
            flags,
            mask,
            !denyAce,
            denyAce,
            objectAce,
            objectTypePresent,
            inheritedObjectTypePresent,
            objectTypeKey ?? string.Empty,
            Convert.ToHexString(value.AsSpan(sidOffset, sidLength)));
        return true;
    }

    private static bool TryReadAceHeader(byte[] value, int offset, int limit, out int size)
    {
        size = 0;
        if (offset < 0 || offset > limit - 4)
            return false;
        size = BinaryPrimitives.ReadUInt16LittleEndian(value.AsSpan(offset + 2, 2));
        return size >= 4 && (size & 3) == 0 && size <= limit - offset;
    }

    private static bool TryReadOffset(byte[] value, int offset, out int result)
    {
        result = 0;
        if (offset < 0 || offset > value.Length - 4)
            return false;
        var raw = BinaryPrimitives.ReadUInt32LittleEndian(value.AsSpan(offset, 4));
        if (raw > int.MaxValue)
            return false;
        result = (int)raw;
        return true;
    }

    private static bool TryReadSid(byte[] value, int offset, int limit, out int length)
    {
        return TryReadSid(value.AsSpan(), offset, limit, out length);
    }

    private static bool TryReadSid(ReadOnlySpan<byte> value, int offset, int limit, out int length)
    {
        length = 0;
        if (offset < 0 || offset > limit - 8 || limit > value.Length)
            return false;
        if (value[offset] != 1)
            return false;
        var count = value[offset + 1];
        if (count is < 1 or > 15)
            return false;
        length = 8 + (count * 4);
        return length <= MaximumSidBytes && length <= limit - offset;
    }

    private static bool TrySidKey(string? value, out string key)
    {
        key = string.Empty;
        if (string.IsNullOrWhiteSpace(value) || value.Length > MaximumSidBytes * 2 || (value.Length & 1) != 0)
            return false;
        byte[] bytes;
        try
        {
            bytes = Convert.FromHexString(value);
        }
        catch (FormatException)
        {
            return false;
        }

        if (!TryReadSid(bytes, 0, bytes.Length, out var length) || length != bytes.Length)
            return false;
        key = Convert.ToHexString(bytes);
        return true;
    }

    private readonly record struct ParsedAce(
        int Size,
        byte Flags,
        uint Mask,
        bool AllowAce,
        bool Deny,
        bool ObjectAce,
        bool ObjectTypePresent,
        bool InheritedObjectTypePresent,
        string ObjectTypeKey,
        string SidKey);

    private readonly record struct DescriptorSegment(int Start, int End, DescriptorSegmentKind Kind);

    private enum DescriptorSegmentKind
    {
        OwnerOrGroup,
        Acl
    }
}
