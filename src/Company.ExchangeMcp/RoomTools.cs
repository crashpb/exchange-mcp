using System.ComponentModel;
using System.Globalization;
using System.Security.Claims;
using Company.ExchangeMcp.Exchange;
using Company.ExchangeMcp.Security;
using ModelContextProtocol;
using ModelContextProtocol.Protocol;
using ModelContextProtocol.Server;

namespace Company.ExchangeMcp;

[McpServerToolType]
public sealed class RoomTools(EwsClient exchange, MailboxAccess access, AuditLog audit)
{
    [McpServerTool(Name = "calendar_list_room_lists", ReadOnly = true, Destructive = false, Idempotent = true, OpenWorld = true)]
    [Description("List Exchange room lists visible to the signed-in employee. An empty result is a valid outcome when the organization has not published room lists.")]
    public Task<object> ListRoomLists(ClaimsPrincipal user, CancellationToken cancellationToken) =>
        Run(user, MailboxAccess.Read, "calendar_list_room_lists", async (identity, ct) =>
        {
            var items = await exchange.ListRoomListsAsync(identity.Mailbox, ct).ConfigureAwait(false);
            return (object)new
            {
                status = "ok",
                count = items.Count,
                items = items.Select(ToAddressView).ToArray(),
                contentTrust = "untrusted_directory_content"
            };
        }, cancellationToken);

    [McpServerTool(Name = "calendar_list_rooms", ReadOnly = true, Destructive = false, Idempotent = true, OpenWorld = true)]
    [Description("List rooms in one Exchange room list. Supply the room-list email address returned by calendar_list_room_lists; an empty result is valid.")]
    public Task<object> ListRooms(ClaimsPrincipal user,
        [Description("Plain email address of an Exchange room list returned by calendar_list_room_lists.")] string roomListAddress,
        CancellationToken cancellationToken) =>
        Run(user, MailboxAccess.Read, "calendar_list_rooms", async (identity, ct) =>
        {
            if (string.IsNullOrWhiteSpace(roomListAddress) || !IsPlainAddress(roomListAddress))
                throw new McpException("Supply one plain room-list email address.");
            access.ValidateRecipients([roomListAddress]);
            var items = await exchange.ListRoomsAsync(identity.Mailbox, roomListAddress, ct).ConfigureAwait(false);
            return (object)new
            {
                status = "ok",
                roomListAddress,
                count = items.Count,
                items = items.Select(ToAddressView).ToArray(),
                contentTrust = "untrusted_directory_content"
            };
        }, cancellationToken);

    [McpServerTool(Name = "calendar_find_meeting_times", ReadOnly = true, Destructive = false, Idempotent = true, OpenWorld = true)]
    [Description("Find bounded meeting slots from Exchange free/busy data. Results contain availability intervals only; no event subjects or locations are returned. No invitations are sent.")]
    public Task<object> FindMeetingTimes(ClaimsPrincipal user,
        [Description("Range start as an ISO-8601 timestamp with an explicit UTC offset.")] string start,
        [Description("Range end as an ISO-8601 timestamp with an explicit UTC offset; the range is at most 31 days.")] string end,
        [Description("Plain email addresses for attendees and rooms, maximum 100.")] string[] participants,
        [Description("Meeting duration in minutes.")] int durationMinutes,
        CancellationToken cancellationToken,
        [Description("Windows or IANA time-zone identifier used to label the returned times.")] string timeZone = "UTC",
        [Description("Candidate step and free/busy interval in minutes.")] int slotMinutes = 30,
        [Description("Maximum suggestions returned; truncation is surfaced explicitly.")] int maxSuggestions = 20) =>
        Run(user, MailboxAccess.Read, "calendar_find_meeting_times", async (identity, ct) =>
        {
            if (participants is null || participants.Length == 0 || participants.Length > 100)
                throw new McpException("Supply between 1 and 100 participants.");
            access.ValidateRecipients(participants);
            var distinctParticipants = participants
                .Distinct(StringComparer.OrdinalIgnoreCase)
                .ToArray();
            var range = ParseRange(start, end);
            if (range.Start >= range.End) throw new McpException("The availability range must end after it starts.");
            var zone = ValidateTimeZone(timeZone);
            if (durationMinutes is < 5 or > 1_440)
                throw new McpException("durationMinutes must be between 5 and 1440.");
            if (slotMinutes is < 5 or > 1_440)
                throw new McpException("slotMinutes must be between 5 and 1440.");
            if (maxSuggestions is < 1 or > 100)
                throw new McpException("maxSuggestions must be between 1 and 100.");
            if (range.End - range.Start > TimeSpan.FromDays(31))
                throw new McpException("The free/busy range must be at most 31 days.");
            if (range.End - range.Start < TimeSpan.FromMinutes(durationMinutes))
                throw new McpException("The requested duration does not fit within the supplied range.");

            var availability = await exchange.GetFreeBusyAsync(
                identity.Mailbox,
                distinctParticipants,
                range.Start.ToUniversalTime(),
                range.End.ToUniversalTime(),
                slotMinutes,
                ct).ConfigureAwait(false);
            if (availability.Count != distinctParticipants.Length
                || !availability.Select(x => x.Mailbox).Order(StringComparer.OrdinalIgnoreCase)
                    .SequenceEqual(distinctParticipants.Order(StringComparer.OrdinalIgnoreCase), StringComparer.OrdinalIgnoreCase)
                || availability.Any(x => x.ViewType is not ("FreeBusy" or "FreeBusyMerged" or "Detailed" or "DetailedMerged")
                    || (!x.HasEventArray && !CompleteMerged(x, range.Start, range.End, slotMinutes))))
                throw new McpException("Exchange did not return usable free/busy data for every participant. No availability can be inferred.");
            var views = availability.Select(ToAvailabilityView).ToArray();
            var suggestions = new List<EwsMeetingSuggestion>();
            DateTimeOffset? nextStart = null;
            for (var candidate = range.Start;
                 candidate + TimeSpan.FromMinutes(durationMinutes) <= range.End;
                 candidate = candidate.AddMinutes(slotMinutes))
            {
                var candidateEnd = candidate.AddMinutes(durationMinutes);
                if (!availability.All(x => IsAvailable(x, candidate, candidateEnd, range.Start, slotMinutes)))
                    continue;
                if (suggestions.Count == maxSuggestions)
                {
                    nextStart = candidate;
                    break;
                }

                suggestions.Add(new EwsMeetingSuggestion(TimeZoneInfo.ConvertTime(candidate, zone),
                    TimeZoneInfo.ConvertTime(candidateEnd, zone), distinctParticipants));
            }

            var truncated = nextStart is not null;
            return (object)new
            {
                status = suggestions.Count == 0 ? "no_available_slot" : truncated ? "partial" : "ok",
                timeZone,
                rangeStart = TimeZoneInfo.ConvertTime(range.Start, zone),
                rangeEnd = TimeZoneInfo.ConvertTime(range.End, zone),
                durationMinutes,
                slotMinutes,
                participantCount = distinctParticipants.Length,
                suggestions = suggestions.Select(x => new
                {
                    start = x.Start,
                    end = x.End,
                    participants = x.Participants
                }).ToArray(),
                truncated,
                nextStart = nextStart is null ? null : (DateTimeOffset?)TimeZoneInfo.ConvertTime(nextStart.Value, zone),
                participants = views
            };
        }, cancellationToken);

    private static object ToAddressView(EwsRoomAddress address) => new
    {
        name = address.Name,
        address = address.Address,
        routingType = address.RoutingType,
        mailboxType = address.MailboxType
    };

    private static object ToAvailabilityView(EwsFreeBusyResult result) => new
    {
        address = result.Mailbox,
        viewType = result.ViewType,
        busyBlocks = result.Events
            .Where(x => !string.Equals(x.BusyType, "Free", StringComparison.Ordinal))
            .Select(x => new { start = x.Start, end = x.End, busyType = x.BusyType })
            .ToArray()
    };

    private static bool CompleteMerged(EwsFreeBusyResult result, DateTimeOffset start, DateTimeOffset end, int interval) =>
        result.MergedFreeBusy is { } merged && merged.Length == (int)Math.Ceiling((end - start).TotalMinutes / interval)
        && merged.All(x => x is >= '0' and <= '4');

    private static bool IsAvailable(EwsFreeBusyResult result, DateTimeOffset start, DateTimeOffset end,
        DateTimeOffset rangeStart, int interval)
    {
        if (result.HasEventArray)
            return !result.Events.Any(x => !string.Equals(x.BusyType, "Free", StringComparison.Ordinal)
                && x.Start < end && x.End > start);
        var first = (int)Math.Floor((start - rangeStart).TotalMinutes / interval);
        var last = (int)Math.Ceiling((end - rangeStart).TotalMinutes / interval);
        return result.MergedFreeBusy![first..last].All(x => x == '0');
    }

    private static (DateTimeOffset Start, DateTimeOffset End) ParseRange(string start, string end) =>
        (ParseTimestamp(start, nameof(start)), ParseTimestamp(end, nameof(end)));

    private static DateTimeOffset ParseTimestamp(string value, string name)
    {
        if (string.IsNullOrWhiteSpace(value) || value.Length > 64
            || !DateTimeOffset.TryParse(value, CultureInfo.InvariantCulture, DateTimeStyles.RoundtripKind, out var parsed)
            || (!value.EndsWith('Z') && !value.Contains('+') && value.LastIndexOf('-') <= 9))
            throw new McpException($"{name} must be an ISO-8601 timestamp with an explicit UTC offset.");
        return parsed;
    }

    private static bool IsPlainAddress(string value)
    {
        try
        {
            var parsed = new System.Net.Mail.MailAddress(value);
            return string.Equals(parsed.Address, value, StringComparison.OrdinalIgnoreCase)
                && value.IndexOfAny(['\r', '\n']) < 0;
        }
        catch (FormatException)
        {
            return false;
        }
    }

    private static TimeZoneInfo ValidateTimeZone(string value)
    {
        if (string.IsNullOrWhiteSpace(value) || value.Length > 128 || value.Any(char.IsControl))
            throw new McpException("timeZone must be a valid Windows or IANA time-zone identifier.");
        try { return TimeZoneInfo.FindSystemTimeZoneById(value); }
        catch (TimeZoneNotFoundException) { throw new McpException("timeZone is not recognized by the server."); }
        catch (InvalidTimeZoneException) { throw new McpException("timeZone is invalid."); }
    }

    private async Task<T> Run<T>(ClaimsPrincipal user, string scope, string operation,
        Func<MailboxIdentity, CancellationToken, Task<T>> action, CancellationToken cancellationToken)
    {
        var identity = access.Require(user, scope);
        var operationId = Guid.NewGuid().ToString("N");
        await audit.RecordAsync(identity, operation, "started", operationId, cancellationToken).ConfigureAwait(false);
        T result;
        try { result = await action(identity, cancellationToken).ConfigureAwait(false); }
        catch (InputRequiredException)
        {
            await audit.RecordAsync(identity, operation, "approval_required", operationId, CancellationToken.None).ConfigureAwait(false);
            throw;
        }
        catch
        {
            await audit.RecordAsync(identity, operation, "failed_or_uncertain", operationId, CancellationToken.None).ConfigureAwait(false);
            throw;
        }
        try { await audit.RecordAsync(identity, operation, "completed", operationId, CancellationToken.None).ConfigureAwait(false); }
        catch { throw new McpException("The operation completed but audit recording failed. Do not repeat it; contact the administrator."); }
        return result;
    }
}
