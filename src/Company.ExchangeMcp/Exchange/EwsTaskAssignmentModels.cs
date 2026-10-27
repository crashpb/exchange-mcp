namespace Company.ExchangeMcp.Exchange;

/// <summary>Native task-assignment metadata carried by Exchange named properties.</summary>
public sealed record EwsTaskAssignmentInfo(
    string? RequestId,
    string? RequestChangeKey,
    string? GlobalTaskId,
    string? AssignerAddress,
    string? AssigneeAddress,
    string? OwnerAddress,
    string? Status,
    int? PercentComplete,
    bool? IsProcessed,
    bool IsReassignment,
    int? Version = null,
    int? State = null,
    int? Ownership = null,
    int? AcceptanceState = null,
    string? AssignerName = null,
    string? OwnerName = null,
    bool? UpdatesEnabled = null,
    bool? CompletionReportEnabled = null,
    string? AssignerStackBase64 = null,
    DateTimeOffset? LastUpdateUtc = null,
    IReadOnlyList<string>? AssignerChainAddresses = null,
    string? LastUserName = null,
    string? LastDelegateName = null,
    bool? Accepted = null,
    int? Mode = null)
{
    public string AcceptanceStatus => DescribeAcceptance(State, Ownership, AcceptanceState, Accepted);

    internal static string DescribeAcceptance(int? state, int? ownership, int? acceptance, bool? accepted) =>
        state == 2 && ownership == 2 && acceptance == 0 && accepted == true ? "accepted"
            : acceptance switch
            {
                0 => "not_assigned",
                2 => "accepted",
                3 => "declined",
                _ => "unknown"
            };
}

public sealed record EwsTaskAssignmentMessage(
    string Id,
    string ChangeKey,
    string ItemClass,
    string Subject,
    string? From,
    string? Sender,
    IReadOnlyList<string> ToRecipients,
    bool IsRead,
    string? GlobalTaskId,
    EwsTask? Task,
    bool IsProcessed,
    bool IsReassignment,
    int? Version = null,
    int? Mode = null,
    IReadOnlyList<string>? CcRecipients = null,
    IReadOnlyList<string>? BccRecipients = null,
    bool InternalAuthenticated = false,
    string? EmbeddedTaskClass = null,
    bool? EmbeddedTaskIsInline = null);

public sealed record EwsTaskAssignmentStatus(
    string? RequestId,
    string? GlobalTaskId,
    string? AssignerAddress,
    string? AssigneeAddress,
    string? OwnerAddress,
    string? Status,
    int? PercentComplete,
    bool? IsProcessed,
    string? Detail,
    int? Version = null,
    int? State = null,
    int? Ownership = null,
    int? AcceptanceState = null,
    string? AssignerName = null,
    string? OwnerName = null,
    bool? UpdatesEnabled = null,
    bool? CompletionReportEnabled = null,
    bool? Accepted = null)
{
    public string AcceptanceStatus => EwsTaskAssignmentInfo.DescribeAcceptance(State, Ownership, AcceptanceState, Accepted);
}

/// <summary>
/// An immutable, server-created action plan. PayloadXml is bounded native EWS XML
/// and is never accepted from a caller; the MCP revalidates all identifiers before send.
/// </summary>
public sealed record EwsTaskAction(
    string Operation,
    string Mailbox,
    string SourceId,
    string SourceChangeKey,
    string StableCorrelation,
    string? OriginalTaskSubject,
    string? AssignerAddress,
    string? AssigneeAddress,
    string? PayloadXml,
    string Digest,
    bool RequiresNativeConfirmation = true,
    string? TaskGlobalId = null,
    double? PercentComplete = null,
    string? Status = null,
    bool IsReassignment = false,
    DateTimeOffset ActionTimeUtc = default,
    EwsTask? PreviewTask = null);

public sealed record EwsTaskActionResult(
    string Operation,
    string SourceId,
    string? ResultItemId,
    string? ResultChangeKey,
    bool Sent,
    bool Applied,
    string Status,
    string? Detail);
