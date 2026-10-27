using System.Buffers.Binary;
using Company.ExchangeMcp.Exchange;

internal sealed partial class Checks
{
    internal Task DirectoryPermissionChecksAsync()
    {
        const string actorSid = "S-1-5-21-111-222-333-1101";
        const string groupSid = "S-1-5-21-111-222-333-2201";
        const string historySid = "S-1-5-21-111-222-333-3301";
        var actor = SidKey(actorSid);
        var group = SidKey(groupSid);
        var history = SidKey(historySid);
        var noGroups = new HashSet<string>(StringComparer.Ordinal);

        ExpectState(DirectoryAclEvaluator.Evaluate(null, actor, noGroups, true, false), "unknown", "missing descriptor");
        ExpectState(DirectoryAclEvaluator.Evaluate(new byte[19], actor, noGroups, true, false), "unknown", "truncated descriptor");
        ExpectState(DirectoryAclEvaluator.Evaluate(Descriptor([], daclPresent: false), actor, noGroups, true, false), "unknown", "absent DACL");
        ExpectState(DirectoryAclEvaluator.Evaluate(Descriptor([], daclPresent: true, nullDacl: true), actor, noGroups, true, false), "unknown", "null DACL");
        ExpectState(DirectoryAclEvaluator.Evaluate(Descriptor([], daclPresent: true, emptyDacl: true), actor, noGroups, true, false), "denied", "empty DACL");

        var directFull = Descriptor([StandardAce(actorSid, allow: true, mask: 0x101)]);
        var directDecision = DirectoryAclEvaluator.Evaluate(directFull, actor, noGroups, true, false);
        ExpectState(directDecision, "allowed", "direct FullAccess");
        Expect(directDecision.Direct && !directDecision.ViaGroup && !directDecision.Inherited,
            "Direct FullAccess was not attributed to the actor.");
        ExpectState(DirectoryAclEvaluator.Evaluate(directFull, actor, noGroups, true, true), "allowed", "broad SendAs mask");

        var grouped = DirectoryAclEvaluator.Evaluate(
            Descriptor([StandardAce(groupSid, allow: true, mask: 1)]), actor,
            new HashSet<string>([group]), true, false);
        ExpectState(grouped, "allowed", "group FullAccess");
        Expect(!grouped.Direct && grouped.ViaGroup, "Group FullAccess was not marked as group-derived.");

        var historyDecision = DirectoryAclEvaluator.Evaluate(
            Descriptor([StandardAce(historySid, allow: true, mask: 1)]), actor,
            new HashSet<string>([history]), true, false);
        ExpectState(historyDecision, "allowed", "SID history FullAccess");
        Expect(historyDecision.ViaGroup, "SID history match was not treated as a non-direct principal.");

        ExpectState(DirectoryAclEvaluator.Evaluate(
            Descriptor([StandardAce(groupSid, allow: true, mask: 1)]), actor, noGroups, true, false),
            "denied", "unrelated group");
        ExpectState(DirectoryAclEvaluator.Evaluate(
            Descriptor([StandardAce("S-1-5-11", allow: true, mask: 1)]), actor, noGroups, true, false),
            "allowed", "Authenticated Users principal");
        ExpectState(DirectoryAclEvaluator.Evaluate(
            Descriptor([StandardAce("S-1-1-0", allow: true, mask: 1)]), actor, noGroups, true, false),
            "allowed", "Everyone principal");

        var denied = DirectoryAclEvaluator.Evaluate(
            Descriptor([
                StandardAce(actorSid, allow: false, mask: 1),
                StandardAce(actorSid, allow: true, mask: 1)
            ]), actor, noGroups, true, false);
        ExpectState(denied, "denied", "explicit deny");
        Expect(denied.MatchingDeny && denied.Direct, "Explicit deny did not retain its matching metadata.");

        var canonicalPrecedence = DirectoryAclEvaluator.Evaluate(
            Descriptor([
                StandardAce(actorSid, allow: true, mask: 1),
                StandardAce(actorSid, allow: false, mask: 1, inherited: true)
            ]), actor, noGroups, true, false);
        ExpectState(canonicalPrecedence, "allowed", "explicit allow before inherited deny");
        Expect(!canonicalPrecedence.Inherited, "Explicit allow was incorrectly reported as inherited.");

        var inheritOnly = DirectoryAclEvaluator.Evaluate(
            Descriptor([
                StandardAce(actorSid, allow: false, mask: 1, inheritOnly: true),
                StandardAce(actorSid, allow: true, mask: 1)
            ]), actor, noGroups, true, false);
        ExpectState(inheritOnly, "allowed", "inherit-only ACE");

        var sendAsGuid = Guid.Parse("ab721a54-1e2f-11d0-9819-00aa0040529b");
        ExpectState(DirectoryAclEvaluator.Evaluate(
            Descriptor([ObjectAce(actorSid, allow: true, mask: 0x100, objectType: sendAsGuid)]),
            actor, noGroups, true, true), "allowed", "object SendAs");
        ExpectState(DirectoryAclEvaluator.Evaluate(
            Descriptor([ObjectAce(actorSid, allow: true, mask: 0x100,
                objectType: Guid.Parse("00000000-0000-0000-0000-000000000001"))]),
            actor, noGroups, true, true), "denied", "wrong SendAs object GUID");
        ExpectState(DirectoryAclEvaluator.Evaluate(
            Descriptor([ObjectAce(actorSid, allow: true, mask: 0x100)]),
            actor, noGroups, true, true), "allowed", "broad SendAs object ACE");
        ExpectState(DirectoryAclEvaluator.Evaluate(
            Descriptor([ObjectAce(actorSid, allow: true, mask: 1, objectType: sendAsGuid)]),
            actor, noGroups, true, false), "unknown", "scoped FullAccess object ACE");
        ExpectState(DirectoryAclEvaluator.Evaluate(
            Descriptor([ObjectAce(actorSid, allow: true, mask: 0x100, inheritedObjectType: sendAsGuid)]),
            actor, noGroups, true, true), "allowed", "effective ACE inherited object scope only controls child propagation");

        ExpectState(DirectoryAclEvaluator.Evaluate(
            Descriptor([UnsupportedAce(actorSid, 9)]), actor, noGroups, true, false),
            "unknown", "callback ACE");
        ExpectState(DirectoryAclEvaluator.Evaluate(
            Descriptor([UnsupportedAce(actorSid, 3)]), actor, noGroups, true, false),
            "unknown", "unsupported ACE");
        var unsupportedFlags = Descriptor([StandardAce(actorSid, allow: true, mask: 1)]);
        unsupportedFlags[29] = 0x20;
        ExpectState(DirectoryAclEvaluator.Evaluate(unsupportedFlags, actor, noGroups, true, false),
            "unknown", "unsupported ACE flags");
        var aclReservedFlags = Descriptor([StandardAce(actorSid, allow: true, mask: 1)]);
        aclReservedFlags[21] = 1;
        ExpectState(DirectoryAclEvaluator.Evaluate(aclReservedFlags, actor, noGroups, true, false),
            "unknown", "reserved ACL flags");
        ExpectState(DirectoryAclEvaluator.Evaluate(
            Descriptor([StandardAce(actorSid, allow: true, mask: 1)]), actor, noGroups, false, false),
            "unknown", "incomplete groups");
        ExpectState(DirectoryAclEvaluator.Evaluate(
            Descriptor([StandardAce(actorSid, allow: true, mask: 0x10000000)]), actor, noGroups, true, false),
            "unknown", "generic access right");

        var malformed = Descriptor([StandardAce(actorSid, allow: true, mask: 1)]);
        BinaryPrimitives.WriteUInt32LittleEndian(malformed.AsSpan(16, 4), 0x7FFFFFFFu);
        ExpectState(DirectoryAclEvaluator.Evaluate(malformed, actor, noGroups, true, false), "unknown", "bad DACL offset");
        var misalignedOffset = Descriptor([StandardAce(actorSid, allow: true, mask: 1)]);
        BinaryPrimitives.WriteUInt32LittleEndian(misalignedOffset.AsSpan(16, 4), 21);
        ExpectState(DirectoryAclEvaluator.Evaluate(misalignedOffset, actor, noGroups, true, false),
            "unknown", "misaligned DACL offset");
        ExpectState(DirectoryAclEvaluator.Evaluate(
            SharedOwnerGroupDescriptor(StandardAce(actorSid, allow: true, mask: 1)),
            actor, noGroups, true, false), "allowed", "shared owner/group SID range");
        ExpectState(DirectoryAclEvaluator.Evaluate(
            PartiallyOverlappingOwnerGroupDescriptor(StandardAce(actorSid, allow: true, mask: 1)),
            actor, noGroups, true, false), "unknown", "partially overlapping owner/group ranges");

        var malformedAce = Descriptor([StandardAce(actorSid, allow: true, mask: 1)]);
        BinaryPrimitives.WriteUInt16LittleEndian(malformedAce.AsSpan(30, 2), 0xFFFF);
        ExpectState(DirectoryAclEvaluator.Evaluate(malformedAce, actor, noGroups, true, false), "unknown", "truncated ACE");
        var shortAce = Descriptor([StandardAce(actorSid, allow: true, mask: 1)]);
        BinaryPrimitives.WriteUInt16LittleEndian(shortAce.AsSpan(30, 2), 4);
        ExpectState(DirectoryAclEvaluator.Evaluate(shortAce, actor, noGroups, true, false), "unknown", "short standard ACE");
        var shortObjectAce = Descriptor([ObjectAce(actorSid, allow: true, mask: 0x100)]);
        BinaryPrimitives.WriteUInt16LittleEndian(shortObjectAce.AsSpan(30, 2), 8);
        ExpectState(DirectoryAclEvaluator.Evaluate(shortObjectAce, actor, noGroups, true, true), "unknown", "short object ACE");

        var sid = SidBytes(actorSid);
        Expect(DirectoryAclEvaluator.SidKey(sid).Equals(Convert.ToHexString(sid), StringComparison.Ordinal),
            "SidKey did not preserve the exact SID bytes.");
        ExpectThrows(() => DirectoryAclEvaluator.SidKey([1, 1, 0]), "SidKey accepted a truncated SID.");
        return Task.CompletedTask;
    }

    private static void ExpectState(PermissionDecision decision, string state, string operation)
    {
        Expect(decision.State == state, $"{operation} returned '{decision.State}' instead of '{state}'.");
    }

    private static void ExpectThrows(Action action, string message)
    {
        try
        {
            action();
        }
        catch (FormatException)
        {
            return;
        }
        throw new InvalidOperationException(message);
    }

    private static byte[] Descriptor(
        IReadOnlyList<byte[]> aces,
        bool daclPresent = true,
        bool emptyDacl = false,
        bool nullDacl = false)
    {
        var dacl = emptyDacl ? new byte[8] : Acl(aces);
        if (emptyDacl)
        {
            dacl[0] = 2;
            BinaryPrimitives.WriteUInt16LittleEndian(dacl.AsSpan(2, 2), 8);
        }

        var descriptor = new byte[20 + (nullDacl ? 0 : dacl.Length)];
        descriptor[0] = 1;
        BinaryPrimitives.WriteUInt16LittleEndian(descriptor.AsSpan(2, 2),
            (ushort)(0x8000 | (daclPresent ? 0x0004 : 0)));
        if (daclPresent && !nullDacl)
        {
            BinaryPrimitives.WriteUInt32LittleEndian(descriptor.AsSpan(16, 4), 20);
            dacl.AsSpan().CopyTo(descriptor.AsSpan(20));
        }
        return descriptor;
    }

    private static byte[] SharedOwnerGroupDescriptor(byte[] ace)
    {
        var sid = SidBytes("S-1-5-21-111-222-333-1101");
        var dacl = Acl([ace]);
        var descriptor = new byte[20 + sid.Length + dacl.Length];
        descriptor[0] = 1;
        BinaryPrimitives.WriteUInt16LittleEndian(descriptor.AsSpan(2, 2), 0x8004);
        BinaryPrimitives.WriteUInt32LittleEndian(descriptor.AsSpan(4, 4), 20);
        BinaryPrimitives.WriteUInt32LittleEndian(descriptor.AsSpan(8, 4), 20);
        BinaryPrimitives.WriteUInt32LittleEndian(descriptor.AsSpan(16, 4), (uint)(20 + sid.Length));
        sid.AsSpan().CopyTo(descriptor.AsSpan(20));
        dacl.AsSpan().CopyTo(descriptor.AsSpan(20 + sid.Length));
        return descriptor;
    }

    private static byte[] PartiallyOverlappingOwnerGroupDescriptor(byte[] ace)
    {
        var dacl = Acl([ace]);
        var descriptor = new byte[44 + dacl.Length];
        descriptor[0] = 1;
        BinaryPrimitives.WriteUInt16LittleEndian(descriptor.AsSpan(2, 2), 0x8004);
        BinaryPrimitives.WriteUInt32LittleEndian(descriptor.AsSpan(4, 4), 20);
        BinaryPrimitives.WriteUInt32LittleEndian(descriptor.AsSpan(8, 4), 24);
        BinaryPrimitives.WriteUInt32LittleEndian(descriptor.AsSpan(16, 4), 44);
        // Owner SID: valid S-1 SID with four subauthorities. Bytes 24..35 also form a valid one-subauthority group SID.
        var owner = new byte[24]
        {
            1, 4, 0, 0, 1, 1, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0
        };
        owner.AsSpan().CopyTo(descriptor.AsSpan(20));
        dacl.AsSpan().CopyTo(descriptor.AsSpan(44));
        return descriptor;
    }

    private static byte[] Acl(IReadOnlyList<byte[]> aces)
    {
        var size = 8 + aces.Sum(ace => ace.Length);
        var acl = new byte[size];
        acl[0] = 4;
        BinaryPrimitives.WriteUInt16LittleEndian(acl.AsSpan(2, 2), checked((ushort)size));
        BinaryPrimitives.WriteUInt16LittleEndian(acl.AsSpan(4, 2), checked((ushort)aces.Count));
        var cursor = 8;
        foreach (var ace in aces)
        {
            ace.AsSpan().CopyTo(acl.AsSpan(cursor));
            cursor += ace.Length;
        }
        return acl;
    }

    private static byte[] StandardAce(string sid, bool allow, uint mask, bool inherited = false, bool inheritOnly = false)
    {
        var sidBytes = SidBytes(sid);
        var ace = new byte[8 + sidBytes.Length];
        ace[0] = allow ? (byte)0 : (byte)1;
        ace[1] = (byte)((inherited ? 0x10 : 0) | (inheritOnly ? 0x08 : 0));
        BinaryPrimitives.WriteUInt16LittleEndian(ace.AsSpan(2, 2), checked((ushort)ace.Length));
        BinaryPrimitives.WriteUInt32LittleEndian(ace.AsSpan(4, 4), mask);
        sidBytes.AsSpan().CopyTo(ace.AsSpan(8));
        return ace;
    }

    private static byte[] ObjectAce(
        string sid,
        bool allow,
        uint mask,
        Guid? objectType = null,
        Guid? inheritedObjectType = null)
    {
        var sidBytes = SidBytes(sid);
        var objectFlags = (objectType is not null ? 1u : 0u)
            | (inheritedObjectType is not null ? 2u : 0u);
        var size = 12 + (objectType is not null ? 16 : 0) + (inheritedObjectType is not null ? 16 : 0) + sidBytes.Length;
        var ace = new byte[size];
        ace[0] = allow ? (byte)5 : (byte)6;
        BinaryPrimitives.WriteUInt16LittleEndian(ace.AsSpan(2, 2), checked((ushort)size));
        BinaryPrimitives.WriteUInt32LittleEndian(ace.AsSpan(4, 4), mask);
        BinaryPrimitives.WriteUInt32LittleEndian(ace.AsSpan(8, 4), objectFlags);
        var cursor = 12;
        if (objectType is Guid objectGuid)
        {
            objectGuid.ToByteArray().AsSpan().CopyTo(ace.AsSpan(cursor));
            cursor += 16;
        }
        if (inheritedObjectType is Guid inheritedGuid)
        {
            inheritedGuid.ToByteArray().AsSpan().CopyTo(ace.AsSpan(cursor));
            cursor += 16;
        }
        sidBytes.AsSpan().CopyTo(ace.AsSpan(cursor));
        return ace;
    }

    private static byte[] UnsupportedAce(string sid, byte type)
    {
        var sidBytes = SidBytes(sid);
        var ace = new byte[8 + sidBytes.Length];
        ace[0] = type;
        BinaryPrimitives.WriteUInt16LittleEndian(ace.AsSpan(2, 2), checked((ushort)ace.Length));
        BinaryPrimitives.WriteUInt32LittleEndian(ace.AsSpan(4, 4), 1);
        sidBytes.AsSpan().CopyTo(ace.AsSpan(8));
        return ace;
    }

    private static byte[] SidBytes(string sid)
    {
        var parts = sid.Split('-');
        var result = new byte[8 + ((parts.Length - 3) * 4)];
        result[0] = 1;
        result[1] = checked((byte)(parts.Length - 3));
        var authority = ulong.Parse(parts[2], System.Globalization.CultureInfo.InvariantCulture);
        for (var i = 0; i < 6; i++)
            result[2 + i] = (byte)(authority >> (40 - (i * 8)));
        for (var i = 3; i < parts.Length; i++)
            BinaryPrimitives.WriteUInt32LittleEndian(result.AsSpan(8 + ((i - 3) * 4), 4),
                uint.Parse(parts[i], System.Globalization.CultureInfo.InvariantCulture));
        return result;
    }

    private static string SidKey(string sid) => Convert.ToHexString(SidBytes(sid));
}
