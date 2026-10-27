using System.Buffers.Binary;
using System.Text;

namespace Company.ExchangeMcp.Exchange;

public sealed record TaskAssignerEntry(string LegacyExchangeDn, string DisplayName);

/// <summary>MS-OXOTASK PidLidTaskAssigners with MS-OXCDATA Address Book EntryIDs.</summary>
public static class TaskAssignerStack
{
    private static readonly byte[] Provider = Convert.FromHexString("DCA740C8C042101AB4B908002B2FE182");
    private static readonly UnicodeEncoding Unicode = new(false, false, true);
    public const int MaxEntries = 8;
    private const int MaxBytes = 32768;

    public static string Append(string? existing, TaskAssignerEntry entry)
    {
        var entries = Parse(existing).ToList();
        if (entries.Any(value => value.LegacyExchangeDn.Equals(entry.LegacyExchangeDn, StringComparison.OrdinalIgnoreCase)))
            throw new InvalidOperationException("Task delegation cannot create a cycle in its assigner chain.");
        if (entries.Count >= MaxEntries)
            throw new InvalidOperationException("The native task assigner chain already contains eight entries.");
        var added = Convert.FromBase64String(Encode([entry]));
        var prior = string.IsNullOrEmpty(existing) ? new byte[4] : Convert.FromBase64String(existing);
        if (prior.Length + added.Length - 4 > MaxBytes) throw Invalid();
        var combined = new byte[prior.Length + added.Length - 4];
        prior.CopyTo(combined, 0);
        added.AsSpan(4).CopyTo(combined.AsSpan(prior.Length));
        BinaryPrimitives.WriteInt32LittleEndian(combined, entries.Count + 1);
        return Convert.ToBase64String(combined);
    }

    public static string Encode(IReadOnlyList<TaskAssignerEntry> entries)
    {
        if (entries.Count is < 1 or > MaxEntries)
            throw new InvalidOperationException("The native task assigner chain must contain one to eight entries.");
        if (entries.Select(entry => entry.LegacyExchangeDn).Distinct(StringComparer.OrdinalIgnoreCase).Count() != entries.Count)
            throw new InvalidOperationException("Task delegation cannot create a cycle in its assigner chain.");
        using var output = new MemoryStream();
        using var writer = new BinaryWriter(output, Encoding.ASCII, leaveOpen: true);
        writer.Write(entries.Count);
        foreach (var entry in entries)
        {
            Validate(entry);
            if (entry.DisplayName.Any(value => value > 126))
                throw new InvalidOperationException("Use an ASCII display name for a new native task assigner entry.");
            using var entryId = new MemoryStream();
            using (var item = new BinaryWriter(entryId, Encoding.ASCII, leaveOpen: true))
            {
                item.Write(0);
                item.Write(Provider);
                item.Write(1);
                item.Write(0);
                item.Write(Encoding.ASCII.GetBytes(entry.LegacyExchangeDn));
                item.Write((byte)0);
            }
            var entryIdBytes = entryId.ToArray();
            var ansiDisplay = Encoding.ASCII.GetBytes(entry.DisplayName);
            var unicodeDisplay = Unicode.GetBytes(entry.DisplayName);
            var entryLength = checked(4 + entryIdBytes.Length + ansiDisplay.Length + 1
                + unicodeDisplay.Length + 2);
            writer.Write(entryLength);
            writer.Write(entryIdBytes.Length);
            writer.Write(entryIdBytes);
            writer.Write(ansiDisplay);
            writer.Write((byte)0);
            writer.Write(unicodeDisplay);
            writer.Write((ushort)0);
        }
        if (output.Length > MaxBytes) throw new InvalidOperationException("The native task assigner chain is too large.");
        return Convert.ToBase64String(output.ToArray());
    }

    public static IReadOnlyList<TaskAssignerEntry> Parse(string? value)
    {
        if (string.IsNullOrEmpty(value)) return [];
        var bytes = Decode(value);
        var count = BinaryPrimitives.ReadInt32LittleEndian(bytes);
        if (count is < 0 or > MaxEntries) throw Invalid();
        var entries = new List<TaskAssignerEntry>(count);
        var offset = ParseEntries(bytes, count, entries);
        if (offset != bytes.Length) throw Invalid();
        return entries;
    }

    /// <summary>
    /// Removes one validated native Outlook decline tail entry while preserving
    /// every byte belonging to the declared entries.  Outlook's decline copy
    /// can report a zero (or otherwise smaller) count while retaining the prior
    /// watcher entry in the serialized value.  Callers must first establish the
    /// fully correlated native decline shape; this method only validates and
    /// trims the bounded wire value.
    /// </summary>
    public static string TrimSingleTrailingEntry(string value)
    {
        var bytes = Decode(value);
        var count = BinaryPrimitives.ReadInt32LittleEndian(bytes);
        if (count is < 0 or >= MaxEntries) throw Invalid();
        var entries = new List<TaskAssignerEntry>(count + 1);
        var declaredEnd = ParseEntries(bytes, count, entries);
        if (declaredEnd >= bytes.Length) throw Invalid();
        var tailEnd = ParseEntries(bytes, 1, entries, declaredEnd);
        if (tailEnd != bytes.Length) throw Invalid();
        if (entries.Count != count + 1)
            throw Invalid();
        var trimmed = bytes[..declaredEnd];
        return Convert.ToBase64String(trimmed);
    }

    private static byte[] Decode(string value)
    {
        if (value.Length > 4 * ((MaxBytes + 2) / 3)) throw Invalid();
        byte[] bytes;
        try { bytes = Convert.FromBase64String(value); }
        catch (FormatException) { throw Invalid(); }
        if (bytes.Length is < 4 or > MaxBytes) throw Invalid();
        return bytes;
    }

    private static int ParseEntries(
        byte[] bytes,
        int count,
        List<TaskAssignerEntry> entries,
        int offset = 4)
    {
        for (var index = 0; index < count; index++)
        {
            if (offset > bytes.Length - 4) throw Invalid();
            var length = BinaryPrimitives.ReadInt32LittleEndian(bytes.AsSpan(offset));
            offset += 4;
            if (length is < 33 or > 4096 || length > bytes.Length - offset) throw Invalid();
            var item = bytes.AsSpan(offset, length);
            offset += length;
            var entry = BinaryPrimitives.ReadInt32LittleEndian(item) == 0
                ? ParseLegacyEntry(item)
                : ParseCanonicalEntry(item);
            Validate(entry);
            if (entries.Any(prior => prior.LegacyExchangeDn.Equals(entry.LegacyExchangeDn, StringComparison.OrdinalIgnoreCase))) throw Invalid();
            entries.Add(entry);
        }
        return offset;
    }

    private static void Validate(TaskAssignerEntry entry)
    {
        if (string.IsNullOrWhiteSpace(entry.LegacyExchangeDn) || entry.LegacyExchangeDn.Length > 1024
            || !entry.LegacyExchangeDn.StartsWith("/o=", StringComparison.OrdinalIgnoreCase)
            || entry.LegacyExchangeDn.Any(value => value < 32 || value > 126)
            || string.IsNullOrWhiteSpace(entry.DisplayName) || entry.DisplayName.Length > 512
            || entry.DisplayName.Any(char.IsControl)) throw Invalid();
    }

    private static InvalidOperationException Invalid() => new("The native task assigner chain is malformed or unsupported.");

    private static TaskAssignerEntry ParseCanonicalEntry(ReadOnlySpan<byte> item)
    {
        if (item.Length < 4)
            throw Invalid();
        var entryIdLength = BinaryPrimitives.ReadInt32LittleEndian(item);
        if (entryIdLength is < 29 or > 4096 || entryIdLength > item.Length - 4)
            throw Invalid();
        var entryId = item.Slice(4, entryIdLength);
        var trailing = item[(4 + entryIdLength)..];
        var (dn, display) = ParseEntryIdAndDisplay(entryId, trailing, requireEntryIdEnd: true);
        return new TaskAssignerEntry(dn, display);
    }

    private static TaskAssignerEntry ParseLegacyEntry(ReadOnlySpan<byte> item)
    {
        var (dn, display) = ParseEntryIdAndDisplay(item, [], requireEntryIdEnd: false);
        return new TaskAssignerEntry(dn, display);
    }

    private static (string Dn, string Display) ParseEntryIdAndDisplay(
        ReadOnlySpan<byte> entryId,
        ReadOnlySpan<byte> trailing,
        bool requireEntryIdEnd)
    {
        if (entryId.Length < 29 || BinaryPrimitives.ReadInt32LittleEndian(entryId) != 0
            || !entryId.Slice(4, 16).SequenceEqual(Provider)
            || BinaryPrimitives.ReadInt32LittleEndian(entryId[20..]) != 1
            || BinaryPrimitives.ReadInt32LittleEndian(entryId[24..]) is not (0 or 4 or 6))
            throw Invalid();
        var dnEnd = entryId[28..].IndexOf((byte)0);
        if (dnEnd < 1) throw Invalid();
        var dn = Encoding.ASCII.GetString(entryId.Slice(28, dnEnd));
        var displayBytes = entryId[(29 + dnEnd)..];
        if (requireEntryIdEnd && !displayBytes.IsEmpty) throw Invalid();
        if (!trailing.IsEmpty)
            displayBytes = trailing;
        var ansiEnd = displayBytes.IndexOf((byte)0);
        if (ansiEnd < 0) throw Invalid();
        var unicode = displayBytes[(ansiEnd + 1)..];
        if (unicode.Length < 2 || unicode.Length % 2 != 0 || unicode[^1] != 0 || unicode[^2] != 0) throw Invalid();
        string display;
        try { display = Unicode.GetString(unicode[..^2]); }
        catch (DecoderFallbackException) { throw Invalid(); }
        return (dn, display);
    }
}
