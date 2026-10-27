namespace Company.ExchangeMcp.Exchange;

public sealed record EwsRoomAddress(
    string Name,
    string Address,
    string RoutingType,
    string MailboxType);

public sealed record EwsMeetingBusyBlock(
    DateTimeOffset Start,
    DateTimeOffset End,
    string BusyType);

public sealed record EwsMeetingParticipantAvailability(
    string Address,
    IReadOnlyList<EwsMeetingBusyBlock> BusyBlocks);

public sealed record EwsMeetingSuggestion(
    DateTimeOffset Start,
    DateTimeOffset End,
    IReadOnlyList<string> Participants);
