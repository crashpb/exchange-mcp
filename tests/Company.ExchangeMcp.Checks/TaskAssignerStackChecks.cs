using System.Buffers.Binary;
using System.DirectoryServices.Protocols;
using System.Text;
using Company.ExchangeMcp.Exchange;
using Company.ExchangeMcp.Security;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;

internal sealed partial class Checks
{
    private async Task TaskAssignerStackChecksAsync()
    {
        AssertTaskAssignerWireRoundTrip();
        AssertTaskAssignerAppendPreservesNativeEntry();
        AssertTaskAssignerLimitsAndCycles();
        AssertTaskAssignerMalformedBytesFailClosed();
        await AssertLdapTaskAssignerLookupAsync();
    }

    private static void AssertTaskAssignerWireRoundTrip()
    {
        var entries = new[]
        {
            new TaskAssignerEntry("/o=Example/ou=Exchange Administrative Group/cn=Recipients/cn=alice", "Alice Example"),
            new TaskAssignerEntry("/o=Example/ou=Exchange Administrative Group/cn=Recipients/cn=bob", "Bob")
        };

        var encoded = TaskAssignerStack.Encode(entries);
        var bytes = Convert.FromBase64String(encoded);
        Expect(BinaryPrimitives.ReadInt32LittleEndian(bytes) == 2,
            "The assigner stack did not write the cAssigners count.");
        var firstOuterLength = BinaryPrimitives.ReadInt32LittleEndian(bytes.AsSpan(4));
        var firstEntryIdLength = BinaryPrimitives.ReadInt32LittleEndian(bytes.AsSpan(8));
        Expect(firstOuterLength == firstEntryIdLength + 4
                + Encoding.ASCII.GetByteCount(entries[0].DisplayName) + 1
                + Encoding.Unicode.GetByteCount(entries[0].DisplayName) + 2,
            "The assigner stack did not write the canonical inner EntryID length prefix.");
        Expect(TaskAssignerWire.TryRead(bytes, 4, out var first, out var nextOffset),
            "The first assigner entry did not follow the MS-OXCDATA structure.");
        Expect(first.Flags == 0 && first.Provider.SequenceEqual(TaskAssignerWire.Provider)
            && first.Version == 1 && first.Type == 0
            && first.LegacyExchangeDn == entries[0].LegacyExchangeDn
            && first.AnsiDisplayName == entries[0].DisplayName
            && first.UnicodeDisplayName == entries[0].DisplayName,
            "The assigner entry flags, provider, version, type, DN, or display names were encoded incorrectly.");
        Expect(TaskAssignerWire.TryRead(bytes, nextOffset, out var second, out var endOffset)
            && endOffset == bytes.Length
            && second.LegacyExchangeDn == entries[1].LegacyExchangeDn,
            "The assigner stack did not contain exactly the declared entries.");

        var parsed = TaskAssignerStack.Parse(encoded);
        Expect(parsed.Count == entries.Length
            && parsed.Zip(entries).All(pair => pair.First == pair.Second),
            "A valid native assigner stack did not round-trip without changing its values.");

        // The empty stack is used while constructing the first assignment and is valid on the wire.
        Expect(TaskAssignerStack.Parse(Convert.ToBase64String(BitConverter.GetBytes(0))).Count == 0,
            "A valid zero-entry assigner stack was rejected.");

        var legacy = TaskAssignerWire.EncodeLegacy(
            "/o=Example/ou=Exchange Administrative Group/cn=Recipients/cn=legacy", "Legacy User", 0,
            Encoding.ASCII.GetBytes("Legacy User"));
        var parsedLegacy = TaskAssignerStack.Parse(legacy);
        Expect(parsedLegacy.Count == 1 && parsedLegacy[0].DisplayName == "Legacy User",
            "A validated legacy unprefixed assigner stack was not retained for existing MCP tasks.");

        var retainedTail = Convert.FromBase64String(TaskAssignerStack.Encode([
            new TaskAssignerEntry("/o=Example/ou=Exchange Administrative Group/cn=Recipients/cn=tail", "Tail")]))
            .ToArray();
        BinaryPrimitives.WriteInt32LittleEndian(retainedTail.AsSpan(), 0);
        var trimmed = TaskAssignerStack.TrimSingleTrailingEntry(Convert.ToBase64String(retainedTail));
        Expect(Convert.FromBase64String(trimmed).SequenceEqual(BitConverter.GetBytes(0)),
            "The native decline stack normalizer did not preserve the declared zero-entry bytes.");
        AssertInvalid(() => TaskAssignerStack.TrimSingleTrailingEntry(encoded),
            "The native decline stack normalizer accepted a stack without exactly one retained tail entry.");
        var twoRetainedTails = Convert.FromBase64String(TaskAssignerStack.Encode([
            new TaskAssignerEntry("/o=Example/ou=Exchange Administrative Group/cn=Recipients/cn=tail-one", "Tail One"),
            new TaskAssignerEntry("/o=Example/ou=Exchange Administrative Group/cn=Recipients/cn=tail-two", "Tail Two")]))
            .ToArray();
        BinaryPrimitives.WriteInt32LittleEndian(twoRetainedTails.AsSpan(), 0);
        AssertInvalid(() => TaskAssignerStack.TrimSingleTrailingEntry(Convert.ToBase64String(twoRetainedTails)),
            "The native decline stack normalizer accepted more than one retained tail entry.");
        AssertInvalid(() => TaskAssignerStack.TrimSingleTrailingEntry(
                Convert.ToBase64String(retainedTail.Concat([byte.MaxValue]).ToArray())),
            "The native decline stack normalizer accepted bytes after the retained tail entry.");
    }

    private static void AssertTaskAssignerAppendPreservesNativeEntry()
    {
        // A real Exchange entry may use an address-book type other than the locally-created type 0.
        // Keep its original bytes: re-encoding it can lose its provider-specific ANSI display name.
        var existing = TaskAssignerWire.Encode(
            "/o=Example/ou=Exchange Administrative Group/cn=Recipients/cn=legacy",
            "Müller", type: 4, ansiDisplayName: Encoding.Latin1.GetBytes("M\xFCller"));
        var existingBytes = Convert.FromBase64String(existing);

        var appended = TaskAssignerStack.Append(existing,
            new TaskAssignerEntry("/o=Example/ou=Exchange Administrative Group/cn=Recipients/cn=new", "New User"));
        var appendedBytes = Convert.FromBase64String(appended);

        Expect(BinaryPrimitives.ReadInt32LittleEndian(appendedBytes) == 2,
            "Appending an assigner did not update cAssigners.");
        Expect(appendedBytes.AsSpan(4, existingBytes.Length - 4).SequenceEqual(existingBytes.AsSpan(4)),
            "Appending an assigner re-encoded or changed an existing native EntryID.");
        var parsed = TaskAssignerStack.Parse(appended);
        Expect(parsed.Count == 2 && parsed[0].DisplayName == "Müller"
            && parsed[1].DisplayName == "New User",
            "Appending an assigner did not preserve the Unicode names in the stack.");

        var newNonAscii = new TaskAssignerEntry(
            "/o=Example/ou=Exchange Administrative Group/cn=Recipients/cn=unicode", "Müller");
        string nonAsciiEncoded;
        try
        {
            nonAsciiEncoded = TaskAssignerStack.Encode([newNonAscii]);
        }
        catch (InvalidOperationException)
        {
            // Rejecting a display name when the configured ANSI code page cannot represent it is safe.
            nonAsciiEncoded = string.Empty;
        }
        if (nonAsciiEncoded.Length > 0)
        {
            var bytes = Convert.FromBase64String(nonAsciiEncoded);
            Expect(TaskAssignerWire.TryRead(bytes, 4, out var item, out _),
                "The non-ASCII assigner entry could not be inspected.");
            Expect(item.AnsiDisplayName != "M?ller",
                "A non-ASCII display name was silently replaced with '?' in the PtypString8 field.");
        }
    }

    private static void AssertTaskAssignerLimitsAndCycles()
    {
        var entries = Enumerable.Range(0, TaskAssignerStack.MaxEntries)
            .Select(index => new TaskAssignerEntry(
                $"/o=Example/ou=Exchange Administrative Group/cn=Recipients/cn=user{index}",
                $"User {index}"))
            .ToArray();
        var eight = TaskAssignerStack.Encode(entries);
        Expect(TaskAssignerStack.Parse(eight).Count == TaskAssignerStack.MaxEntries,
            "The maximum eight-entry assigner stack was not accepted.");

        AssertInvalid(() => TaskAssignerStack.Append(eight,
            new TaskAssignerEntry("/o=Example/ou=Exchange Administrative Group/cn=Recipients/cn=overflow", "Overflow")),
            "The assigner stack accepted a ninth entry.");
        AssertInvalid(() => TaskAssignerStack.Append(eight,
            new TaskAssignerEntry(entries[3].LegacyExchangeDn.ToUpperInvariant(), "Cycle")),
            "The assigner stack accepted a case-insensitive assigner cycle.");
        AssertInvalid(() => TaskAssignerStack.Encode([entries[0], entries[0]]),
            "The assigner stack accepted a duplicate assigner in a newly encoded chain.");
        AssertInvalid(() => TaskAssignerStack.Encode([
            new TaskAssignerEntry("/o=Example/ou=Exchange Administrative Group/cn=Recipients/cn=bad\n", "Bad")]),
            "The assigner stack accepted control characters in the legacy Exchange DN.");
    }

    private static void AssertTaskAssignerMalformedBytesFailClosed()
    {
        var valid = Convert.FromBase64String(TaskAssignerStack.Encode([
            new TaskAssignerEntry("/o=Example/ou=Exchange Administrative Group/cn=Recipients/cn=valid", "Valid")]))
            .ToArray();

        AssertInvalid(() => TaskAssignerStack.Parse("not-base64"),
            "The assigner stack accepted malformed Base64.");
        AssertInvalid(() => TaskAssignerStack.Parse(Convert.ToBase64String(valid[..^1])),
            "The assigner stack accepted a truncated entry.");

        var trailing = valid.Concat(new byte[] { 0 }).ToArray();
        AssertInvalid(() => TaskAssignerStack.Parse(Convert.ToBase64String(trailing)),
            "The assigner stack accepted trailing data after the declared entries.");

        var wrongFlags = valid.ToArray();
        BinaryPrimitives.WriteInt32LittleEndian(wrongFlags.AsSpan(12), 1);
        AssertInvalid(() => TaskAssignerStack.Parse(Convert.ToBase64String(wrongFlags)),
            "The assigner stack accepted nonzero EntryID flags.");

        var wrongProvider = valid.ToArray();
        wrongProvider[16] ^= 0x01;
        AssertInvalid(() => TaskAssignerStack.Parse(Convert.ToBase64String(wrongProvider)),
            "The assigner stack accepted an unknown Address Book provider UID.");

        var wrongVersion = valid.ToArray();
        BinaryPrimitives.WriteInt32LittleEndian(wrongVersion.AsSpan(32), 2);
        AssertInvalid(() => TaskAssignerStack.Parse(Convert.ToBase64String(wrongVersion)),
            "The assigner stack accepted an unsupported Address Book EntryID version.");

        var wrongType = valid.ToArray();
        BinaryPrimitives.WriteInt32LittleEndian(wrongType.AsSpan(36), 7);
        AssertInvalid(() => TaskAssignerStack.Parse(Convert.ToBase64String(wrongType)),
            "The assigner stack accepted an unsupported Address Book EntryID type.");

        var invalidUnicode = valid.ToArray();
        var unicodeOffset = TaskAssignerWire.FindUnicodeOffset(invalidUnicode, 4);
        invalidUnicode[unicodeOffset] = 0x00;
        invalidUnicode[unicodeOffset + 1] = 0xD8; // lone UTF-16 high surrogate
        invalidUnicode[unicodeOffset + 2] = 0x00;
        invalidUnicode[unicodeOffset + 3] = 0x00;
        AssertInvalid(() => TaskAssignerStack.Parse(Convert.ToBase64String(invalidUnicode)),
            "The assigner stack accepted invalid UTF-16 display data.");

        var excessiveCount = valid.ToArray();
        BinaryPrimitives.WriteInt32LittleEndian(excessiveCount.AsSpan(0), TaskAssignerStack.MaxEntries + 1);
        AssertInvalid(() => TaskAssignerStack.Parse(Convert.ToBase64String(excessiveCount)),
            "The assigner stack accepted more than eight declared assigners.");

        var declaredOverrun = valid.ToArray();
        BinaryPrimitives.WriteInt32LittleEndian(declaredOverrun.AsSpan(4), 4096);
        AssertInvalid(() => TaskAssignerStack.Parse(Convert.ToBase64String(declaredOverrun)),
            "The assigner stack accepted an entry length beyond the available bytes.");

        var negativeLength = valid.ToArray();
        BinaryPrimitives.WriteInt32LittleEndian(negativeLength.AsSpan(4), -1);
        AssertInvalid(() => TaskAssignerStack.Parse(Convert.ToBase64String(negativeLength)),
            "The assigner stack accepted a negative entry length.");

        var innerOverrun = valid.ToArray();
        BinaryPrimitives.WriteInt32LittleEndian(innerOverrun.AsSpan(8), 4096);
        AssertInvalid(() => TaskAssignerStack.Parse(Convert.ToBase64String(innerOverrun)),
            "The assigner stack accepted an inner EntryID length beyond the available bytes.");

        var negativeInnerLength = valid.ToArray();
        BinaryPrimitives.WriteInt32LittleEndian(negativeInnerLength.AsSpan(8), -1);
        AssertInvalid(() => TaskAssignerStack.Parse(Convert.ToBase64String(negativeInnerLength)),
            "The assigner stack accepted a negative inner EntryID length.");

        var oversized = new byte[32_769];
        BinaryPrimitives.WriteInt32LittleEndian(oversized.AsSpan(), 0);
        AssertInvalid(() => TaskAssignerStack.Parse(Convert.ToBase64String(oversized)),
            "The assigner stack accepted a value over its bounded byte limit.");
    }

    private static async Task AssertLdapTaskAssignerLookupAsync()
    {
        var options = Options.Create(new DirectoryPermissionOptions
        {
            Host = "ldap.example.test",
            Port = 636,
            BaseDn = "DC=example,DC=test",
            TimeoutSeconds = 8
        });
        var validDn = "/o=Example/ou=Exchange Administrative Group/cn=Recipients/cn=alice";
        var factory = new TaskAssignerRecordingFactory([
            [new LdapSearchEntry("CN=Alice,DC=example,DC=test",
                new Dictionary<string, IReadOnlyList<string>>(StringComparer.OrdinalIgnoreCase)
                {
                    ["legacyExchangeDN"] = [validDn], ["displayName"] = ["Alice Example"]
                }, new Dictionary<string, IReadOnlyList<byte[]>>(StringComparer.OrdinalIgnoreCase))]
        ]);
        var reader = new LdapMailboxPermissionReader(options, factory,
            NullLogger<LdapMailboxPermissionReader>.Instance);
        var result = await reader.ResolveTaskAssignerAsync("alice@example.test", CancellationToken.None);
        Expect(result.LegacyExchangeDn == validDn && result.DisplayName == "Alice Example",
            "LDAP task assigner lookup did not return the unique Exchange DN and display name.");
        Expect(factory.Records.Count == 1 && factory.Records[0].Scope == SearchScope.Subtree
            && factory.Records[0].Filter.Contains("(objectClass=user)", StringComparison.Ordinal)
            && factory.Records[0].Attributes.SequenceEqual(["legacyExchangeDN", "displayName"]),
            "LDAP task assigner lookup used an unexpected scope, filter, or attribute set.");

        const string injectionMailbox = "\"a*)(mail=*)\"@example.test";
        var injectionFactory = new TaskAssignerRecordingFactory([[
            new LdapSearchEntry("CN=Alice,DC=example,DC=test",
                Text("legacyExchangeDN", validDn), EmptyBinary())
        ]]);
        await new LdapMailboxPermissionReader(options, injectionFactory,
            NullLogger<LdapMailboxPermissionReader>.Instance)
            .ResolveTaskAssignerAsync(injectionMailbox, CancellationToken.None);
        var injectionFilter = injectionFactory.Records.Single().Filter;
        Expect(injectionFilter.Contains("\\2a", StringComparison.Ordinal)
            && injectionFilter.Contains("\\28", StringComparison.Ordinal)
            && injectionFilter.Contains("\\29", StringComparison.Ordinal)
            && !injectionFilter.Contains(")(|", StringComparison.Ordinal),
            "LDAP task assigner lookup did not escape wildcard and grouping characters in the mailbox filter.");

        var escapedFactory = new TaskAssignerRecordingFactory([[]]);
        var escapedReader = new LdapMailboxPermissionReader(options, escapedFactory,
            NullLogger<LdapMailboxPermissionReader>.Instance);
        await TaskAssignerAssertThrowsAsync<InvalidOperationException>(() => escapedReader.ResolveTaskAssignerAsync(
            "not a mailbox", CancellationToken.None));
        Expect(escapedFactory.Records.Count == 0,
            "An invalid mailbox identifier reached the LDAP task assigner lookup.");

        foreach (var responses in new IReadOnlyList<LdapSearchEntry>[]
        {
            Array.Empty<LdapSearchEntry>(),
            new[]
            {
                new LdapSearchEntry("CN=One,DC=example,DC=test", EmptyText(), EmptyBinary()),
                new LdapSearchEntry("CN=Two,DC=example,DC=test", EmptyText(), EmptyBinary())
            },
            new[]
            {
                new LdapSearchEntry("CN=Malformed,DC=example,DC=test",
                    Text("legacyExchangeDN", "not-an-x500-dn"), EmptyBinary())
            },
            new[]
            {
                new LdapSearchEntry("CN=Duplicate,DC=example,DC=test",
                    Text("legacyExchangeDN", validDn, validDn), EmptyBinary())
            }
        })
        {
            await TaskAssignerAssertThrowsAsync<InvalidOperationException>(() => new LdapMailboxPermissionReader(
                options, new TaskAssignerRecordingFactory([responses]),
                NullLogger<LdapMailboxPermissionReader>.Instance)
                .ResolveTaskAssignerAsync("alice@example.test", CancellationToken.None));
        }

        var fallbackFactory = new TaskAssignerRecordingFactory([
            [new LdapSearchEntry("CN=Alice,DC=example,DC=test",
                Text("legacyExchangeDN", validDn), EmptyBinary())]
        ]);
        var fallback = await new LdapMailboxPermissionReader(options, fallbackFactory,
            NullLogger<LdapMailboxPermissionReader>.Instance)
            .ResolveTaskAssignerAsync("alice@example.test", CancellationToken.None);
        Expect(fallback.DisplayName == "alice@example.test",
            "LDAP task assigner lookup did not use the mailbox as a deterministic display-name fallback.");

        var nonAsciiFactory = new TaskAssignerRecordingFactory([[
            new LdapSearchEntry("CN=Alice,DC=example,DC=test",
                new Dictionary<string, IReadOnlyList<string>>(StringComparer.OrdinalIgnoreCase)
                {
                    ["legacyExchangeDN"] = [validDn], ["displayName"] = ["Müller"]
                }, EmptyBinary())
        ]]);
        var nonAsciiFallback = await new LdapMailboxPermissionReader(options, nonAsciiFactory,
            NullLogger<LdapMailboxPermissionReader>.Instance)
            .ResolveTaskAssignerAsync("alice@example.test", CancellationToken.None);
        Expect(nonAsciiFallback.DisplayName == "alice@example.test",
            "LDAP task assigner lookup allowed a non-ASCII directory display name into the ANSI native field.");

        using var cancellation = new CancellationTokenSource();
        cancellation.Cancel();
        await TaskAssignerAssertThrowsAsync<OperationCanceledException>(() => new LdapMailboxPermissionReader(
            options, new TaskAssignerRecordingFactory([[]]),
            NullLogger<LdapMailboxPermissionReader>.Instance)
            .ResolveTaskAssignerAsync("alice@example.test", cancellation.Token));

        static IReadOnlyDictionary<string, IReadOnlyList<string>> EmptyText() =>
            new Dictionary<string, IReadOnlyList<string>>(StringComparer.OrdinalIgnoreCase);
        static IReadOnlyDictionary<string, IReadOnlyList<byte[]>> EmptyBinary() =>
            new Dictionary<string, IReadOnlyList<byte[]>>(StringComparer.OrdinalIgnoreCase);
        static IReadOnlyDictionary<string, IReadOnlyList<string>> Text(string name, params string[] values) =>
            new Dictionary<string, IReadOnlyList<string>>(StringComparer.OrdinalIgnoreCase) { [name] = values };
    }

    private static void AssertInvalid(Action action, string message)
    {
        try
        {
            action();
        }
        catch (InvalidOperationException)
        {
            return;
        }
        throw new InvalidOperationException(message);
    }

    private static async Task TaskAssignerAssertThrowsAsync<TException>(Func<Task> action)
        where TException : Exception
    {
        try
        {
            await action();
        }
        catch (TException)
        {
            return;
        }
        throw new InvalidOperationException($"Expected {typeof(TException).Name}.");
    }
}

internal static class TaskAssignerWire
{
    internal static readonly byte[] Provider = Convert.FromHexString("DCA740C8C042101AB4B908002B2FE182");
    private static readonly UnicodeEncoding Unicode = new(false, false, true);

    internal static string Encode(string dn, string displayName, int type, byte[] ansiDisplayName)
    {
        using var entryId = new MemoryStream();
        using (var writer = new BinaryWriter(entryId, Encoding.ASCII, leaveOpen: true))
        {
            writer.Write(0);
            writer.Write(Provider);
            writer.Write(1);
            writer.Write(type);
            writer.Write(Encoding.ASCII.GetBytes(dn));
            writer.Write((byte)0);
        }
        return EncodeCanonical(entryId.ToArray(), displayName, ansiDisplayName);
    }

    internal static string EncodeLegacy(string dn, string displayName, int type, byte[] ansiDisplayName)
    {
        using var item = new MemoryStream();
        using (var writer = new BinaryWriter(item, Encoding.ASCII, leaveOpen: true))
        {
            writer.Write(0);
            writer.Write(Provider);
            writer.Write(1);
            writer.Write(type);
            writer.Write(Encoding.ASCII.GetBytes(dn));
            writer.Write((byte)0);
            writer.Write(ansiDisplayName);
            writer.Write((byte)0);
            writer.Write(Unicode.GetBytes(displayName));
            writer.Write((ushort)0);
        }
        using var stack = new MemoryStream();
        using (var writer = new BinaryWriter(stack, Encoding.ASCII, leaveOpen: true))
        {
            writer.Write(1);
            writer.Write(checked((int)item.Length));
            writer.Write(item.ToArray());
        }
        return Convert.ToBase64String(stack.ToArray());
    }

    private static string EncodeCanonical(byte[] entryId, string displayName, byte[] ansiDisplayName)
    {
        using var stack = new MemoryStream();
        using (var writer = new BinaryWriter(stack, Encoding.ASCII, leaveOpen: true))
        {
            writer.Write(1);
            writer.Write(checked(4 + entryId.Length + ansiDisplayName.Length + 1
                + Unicode.GetByteCount(displayName) + 2));
            writer.Write(entryId.Length);
            writer.Write(entryId);
            writer.Write(ansiDisplayName);
            writer.Write((byte)0);
            writer.Write(Unicode.GetBytes(displayName));
            writer.Write((ushort)0);
        }
        return Convert.ToBase64String(stack.ToArray());
    }

    internal static int FindUnicodeOffset(byte[] stack, int offset)
    {
        var length = BinaryPrimitives.ReadInt32LittleEndian(stack.AsSpan(offset));
        var entryIdLength = BinaryPrimitives.ReadInt32LittleEndian(stack.AsSpan(offset + 4));
        var displayStart = offset + 4 + entryIdLength;
        var ansiEnd = stack.AsSpan(displayStart, length - 4 - entryIdLength).IndexOf((byte)0);
        return displayStart + ansiEnd + 1;
    }

    internal static bool TryRead(byte[] stack, int offset, out TaskAssignerWireItem result, out int nextOffset)
    {
        result = default;
        nextOffset = offset;
        if (offset < 4 || offset > stack.Length - 4) return false;
        var length = BinaryPrimitives.ReadInt32LittleEndian(stack.AsSpan(offset));
        if (length < 0 || offset + 4L + length > stack.Length) return false;
        var item = stack.AsSpan(offset + 4, length);
        if (length < 33) return false;
        var entryIdLength = BinaryPrimitives.ReadInt32LittleEndian(item);
        if (entryIdLength < 29 || entryIdLength > length - 4) return false;
        var entryId = item.Slice(4, entryIdLength);
        var dnEnd = entryId[28..].IndexOf((byte)0);
        if (dnEnd < 1) return false;
        var dnStart = 28;
        if (dnStart + dnEnd + 1 != entryId.Length) return false;
        var displayStart = 4 + entryIdLength;
        var ansiEnd = item[displayStart..].IndexOf((byte)0);
        if (ansiEnd < 0) return false;
        var unicodeStart = displayStart + ansiEnd + 1;
        if (unicodeStart > item.Length - 2) return false;
        var unicode = item[unicodeStart..];
        var unicodeEnd = -1;
        for (var i = 0; i + 1 < unicode.Length; i += 2)
        {
            if (unicode[i] == 0 && unicode[i + 1] == 0)
            {
                unicodeEnd = i;
                break;
            }
        }
        if (unicodeEnd < 0) return false;
        result = new(
            BinaryPrimitives.ReadInt32LittleEndian(entryId),
            entryId.Slice(4, 16).ToArray(),
            BinaryPrimitives.ReadInt32LittleEndian(entryId[20..]),
            BinaryPrimitives.ReadInt32LittleEndian(entryId[24..]),
            Encoding.ASCII.GetString(entryId.Slice(dnStart, dnEnd)),
            Encoding.Latin1.GetString(item.Slice(displayStart, ansiEnd)),
            Unicode.GetString(unicode[..unicodeEnd]));
        nextOffset = offset + 4 + length;
        return true;
    }
}

internal readonly record struct TaskAssignerWireItem(
    int Flags,
    byte[] Provider,
    int Version,
    int Type,
    string LegacyExchangeDn,
    string AnsiDisplayName,
    string UnicodeDisplayName);

internal sealed class TaskAssignerRecordingFactory(
    IReadOnlyList<IReadOnlyList<LdapSearchEntry>> responses) : ILdapSearchFacadeFactory
{
    public List<TaskAssignerLdapCall> Records { get; } = [];

    public ILdapSearchFacade Create() => new RecordingFacade(this, responses);

    private sealed class RecordingFacade(
        TaskAssignerRecordingFactory owner,
        IReadOnlyList<IReadOnlyList<LdapSearchEntry>> responses) : ILdapSearchFacade
    {
        private int call;

        public IReadOnlyList<LdapSearchEntry> Search(
            string baseDn,
            string filter,
            SearchScope scope,
            IReadOnlyList<string> attributes,
            bool requestDaclOnly,
            CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            owner.Records.Add(new TaskAssignerLdapCall(baseDn, filter, scope, attributes.ToArray(), requestDaclOnly));
            return call < responses.Count ? responses[call++] : [];
        }

        public void Dispose() { }
    }
}

internal sealed record TaskAssignerLdapCall(
    string BaseDn,
    string Filter,
    SearchScope Scope,
    IReadOnlyList<string> Attributes,
    bool RequestDaclOnly);
