using System.Text.Json.Serialization;

namespace Company.ExchangeMcp.Exchange;

public sealed record EwsOofSettings(
    string State,
    string ExternalAudience,
    string? StartTime,
    string? EndTime,
    string InternalReply,
    string ExternalReply,
    string Revision = "",
    [property: JsonIgnore] string? DeclineMeetingReply = null,
    [property: JsonIgnore] bool? DeclineEventsForScheduledOof = null,
    [property: JsonIgnore] bool? DeclineAllEventsForScheduledOof = null,
    [property: JsonIgnore] bool? CreateOofEvent = null,
    [property: JsonIgnore] string? OofEventSubject = null,
    [property: JsonIgnore] bool? AutoDeclineFutureRequestsWhenOof = null,
    [property: JsonIgnore] string? OofEventId = null,
    [property: JsonIgnore] string? EventsToDeleteIdsXml = null,
    [property: JsonIgnore] string? AllowExternalOof = null,
    [property: JsonIgnore] string? InternalReplyLanguage = null,
    [property: JsonIgnore] string? ExternalReplyLanguage = null,
    [property: JsonIgnore] string? DeclineMeetingReplyLanguage = null,
    [property: JsonIgnore] bool InternalReplyPresent = true,
    [property: JsonIgnore] bool ExternalReplyPresent = true,
    [property: JsonIgnore] bool DeclineMeetingReplyPresent = false,
    [property: JsonIgnore] string? RawSettingsXml = null);

public sealed record EwsInboxRules(
    bool? OutlookRuleBlobExists,
    IReadOnlyList<EwsInboxRule> Rules,
    string Revision);

public sealed record EwsInboxRule(
    string Id,
    string DisplayName,
    int Priority,
    bool IsEnabled,
    EwsRulePredicates Conditions,
    EwsRuleActions Actions,
    IReadOnlyList<string> UnsupportedActions,
    IReadOnlyList<string> UnsupportedConditions,
    IReadOnlyList<string> UnsupportedExceptions,
    bool IsInError,
    bool IsNotSupported);

public sealed record EwsRulePredicates(
    IReadOnlyList<string> ContainsSubjectStrings,
    IReadOnlyList<string> ContainsBodyStrings,
    IReadOnlyList<string> FromAddresses,
    IReadOnlyList<string> SentToAddresses);

public sealed record EwsRuleActions(
    string? MoveToFolder,
    string? CopyToFolder,
    bool? MarkAsRead,
    IReadOnlyList<string> Categories,
    bool StopProcessingRules);

public sealed record EwsInboxRuleOperation(
    string Kind,
    string? RuleId,
    EwsInboxRule? Rule);
