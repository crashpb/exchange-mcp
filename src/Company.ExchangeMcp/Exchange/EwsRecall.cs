namespace Company.ExchangeMcp.Exchange;

public sealed class RecallPreparationException : InvalidOperationException
{
    internal RecallPreparationException(string phase) : base("Recall preparation failed; no recall was submitted.")
    {
        Phase = phase switch
        {
            "source_folder" or "source_message" or "source_validation" or "mailbox_identity" or "report_tag" => phase,
            _ => throw new ArgumentOutOfRangeException(nameof(phase))
        };
    }

    public string Phase { get; }
    public string Reason => "preparation_failed";
}

public sealed record EwsRecallRequest(
    string Id,
    string ChangeKey,
    string Subject,
    IReadOnlyList<string> To,
    IReadOnlyList<string> Cc,
    IReadOnlyList<string> Bcc,
    string SearchKey,
    string ReportTag);

public sealed record EwsRecallReport(
    string Outcome,
    string Subject,
    string? ReceivedUtc);

public sealed record EwsRecallTracking(
    string ReportTag,
    string SearchKey,
    string Subject,
    int RecipientCount);
