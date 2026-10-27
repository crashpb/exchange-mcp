using System.Globalization;
using System.Security.Cryptography;
using System.Text.Json;
using System.Xml;
using System.Xml.Linq;

namespace Company.ExchangeMcp.Exchange;

public sealed partial class EwsClient
{
    internal const string OpaqueFolderTargetPrefix = "ews-folder-id:";
    private const int MaxOofMessageLength = 1_048_576;
    private const int MaxInboxRules = 1_000;
    private const int MaxRuleStrings = 100;
    private static readonly HashSet<string> RuleDistinguishedFolderIds = new(StringComparer.OrdinalIgnoreCase)
    {
        "calendar", "contacts", "deleteditems", "drafts", "inbox", "junkemail", "journal",
        "msgfolderroot", "notes", "outbox", "sentitems", "tasks", "publicfoldersroot", "root", "searchfolders",
        "recoverableitemsroot", "recoverableitemsdeletions", "recoverableitemsversions",
        "recoverableitemspurges", "syncissues", "conflicts", "localfailures", "serverfailures",
        "recipientcache", "quickcontacts", "conversationhistory", "adminauditlogs", "todosearch",
        "mycontacts", "directory", "imcontactlist", "imcontacts", "imconversationhistory", "peopleconnect",
        "voicemail", "archiveroot", "archivemsgfolderroot", "archivedeleteditems", "archiveinbox",
        "archiverecoverableitemsroot", "archiverecoverableitemsdeletions", "archiverecoverableitemsversions",
        "archiverecoverableitemspurges", "recoverableitemsdiscoveryholds", "archiverecoverableitemsdiscoveryholds",
        "favorites", "mecontact", "personmetadata"
    };

    internal static bool IsRuleDistinguishedFolderId(string value) => RuleDistinguishedFolderIds.Contains(value);

    public async Task<EwsOofSettings> GetOofSettingsAsync(string mailbox, CancellationToken cancellationToken)
    {
        var normalizedMailbox = ValidateMailbox(mailbox);
        var operation = new XElement(M + "GetUserOofSettingsRequest",
            new XElement(T + "Mailbox",
                new XElement(T + "Address", normalizedMailbox),
                new XElement(T + "RoutingType", "SMTP")));
        var document = await SendAsync(normalizedMailbox, operation, cancellationToken,
            responseValidator: ValidateMailboxSettingsResponse).ConfigureAwait(false);
        var response = RequiredElement(document, M + "GetUserOofSettingsResponse");
        var settingsElements = response.Elements().Where(element => element.Name.LocalName == "OofSettings").ToArray();
        if (settingsElements.Length != 1 || settingsElements[0].Name != T + "OofSettings")
            throw new InvalidOperationException("Exchange omitted or misnames OofSettings in the successful response.");
        var settings = settingsElements[0];
        var allowExternal = response.Elements().Where(element => element.Name.LocalName == "AllowExternalOof").ToArray();
        if (allowExternal.Length > 1 || allowExternal.Any(element => element.Name != M + "AllowExternalOof"))
            throw new InvalidOperationException("Exchange returned an unsupported AllowExternalOof shape.");
        return ParseOofSettings(settings, allowExternal.SingleOrDefault()?.Value);
    }

    public async Task SetOofSettingsAsync(string mailbox, EwsOofSettings settings,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(settings);
        var normalizedMailbox = ValidateMailbox(mailbox);
        ValidateOofSettings(settings);
        var eventsToDelete = ParseEventsToDeleteIds(settings.EventsToDeleteIdsXml);
        if (eventsToDelete is not null)
            throw new InvalidOperationException("OOF writes with EventsToDeleteIDs are blocked until calendar deletion approval is implemented.");
        var userSettings = new XElement(T + "UserOofSettings",
            new XElement(T + "OofState", settings.State),
            new XElement(T + "ExternalAudience", settings.ExternalAudience),
            settings.State.Equals("Scheduled", StringComparison.OrdinalIgnoreCase)
                || settings.StartTime is not null || settings.EndTime is not null
                ? new XElement(T + "Duration",
                    settings.StartTime is null ? null : new XElement(T + "StartTime", settings.StartTime),
                    settings.EndTime is null ? null : new XElement(T + "EndTime", settings.EndTime))
                : null,
            BuildOofReply("InternalReply", settings.InternalReplyPresent, settings.InternalReply, settings.InternalReplyLanguage),
            BuildOofReply("ExternalReply", settings.ExternalReplyPresent, settings.ExternalReply, settings.ExternalReplyLanguage),
            BuildOofReply("DeclineMeetingReply", settings.DeclineMeetingReplyPresent,
                settings.DeclineMeetingReply ?? string.Empty, settings.DeclineMeetingReplyLanguage),
            settings.DeclineEventsForScheduledOof is { } declineEvents
                ? new XElement(T + "DeclineEventsForScheduledOOF", declineEvents.ToString().ToLowerInvariant()) : null,
            settings.DeclineAllEventsForScheduledOof is { } declineAllEvents
                ? new XElement(T + "DeclineAllEventsForScheduledOOF", declineAllEvents.ToString().ToLowerInvariant()) : null,
            settings.CreateOofEvent is { } createEvent
                ? new XElement(T + "CreateOOFEvent", createEvent.ToString().ToLowerInvariant()) : null,
            settings.OofEventSubject is null ? null : new XElement(T + "OOFEventSubject", settings.OofEventSubject),
            settings.AutoDeclineFutureRequestsWhenOof is { } autoDecline
                ? new XElement(T + "AutoDeclineFutureRequestsWhenOOF", autoDecline.ToString().ToLowerInvariant()) : null,
            settings.OofEventId is null ? null : new XElement(T + "OOFEventID", settings.OofEventId),
            eventsToDelete);
        var operation = new XElement(M + "SetUserOofSettingsRequest",
            new XElement(T + "Mailbox",
                new XElement(T + "Address", normalizedMailbox),
                new XElement(T + "RoutingType", "SMTP")),
            userSettings);
        _ = await SendAsync(normalizedMailbox, operation, cancellationToken,
            responseValidator: ValidateMailboxSettingsResponse).ConfigureAwait(false);
    }

    public async Task<EwsInboxRules> GetInboxRulesAsync(string mailbox, CancellationToken cancellationToken)
    {
        var normalizedMailbox = ValidateMailbox(mailbox);
        var operation = new XElement(M + "GetInboxRules",
            new XElement(M + "MailboxSmtpAddress", normalizedMailbox));
        var document = await SendAsync(normalizedMailbox, operation, cancellationToken,
            responseValidator: ValidateMailboxSettingsResponse).ConfigureAwait(false);
        var response = RequiredElement(document, M + "GetInboxRulesResponse");
        var blobElement = response.Element(M + "OutlookRuleBlobExists");
        bool? blob = null;
        if (blobElement is not null)
        {
            if (!bool.TryParse(blobElement.Value, out var parsedBlob))
                throw new InvalidOperationException("Exchange returned malformed Outlook client-rule state.");
            blob = parsedBlob;
        }
        var inboxRules = response.Element(M + "InboxRules");
        var rules = inboxRules?.Elements(T + "Rule")
            .Select(ParseInboxRule).ToArray();
        if (rules is not null && rules.Length > MaxInboxRules)
            throw new InvalidOperationException("The Exchange Inbox rule result exceeded the supported limit.");
        return new EwsInboxRules(blob, rules ?? [], Revision(blob, inboxRules));
    }

    public async Task UpdateInboxRulesAsync(string mailbox, EwsInboxRuleOperation operation,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(operation);
        var normalizedMailbox = ValidateMailbox(mailbox);
        var mutation = operation.Kind switch
        {
            "create" when operation.Rule is not null =>
                new XElement(T + "CreateRuleOperation", BuildRule(operation.Rule, includeId: false)),
            "set" when operation.Rule is not null && !string.IsNullOrWhiteSpace(operation.RuleId) =>
                new XElement(T + "SetRuleOperation", BuildRule(operation.Rule with { Id = operation.RuleId }, includeId: true)),
            "delete" when !string.IsNullOrWhiteSpace(operation.RuleId) =>
                new XElement(T + "DeleteRuleOperation", new XElement(T + "RuleId", operation.RuleId)),
            _ => throw new ArgumentException("The Inbox rule operation is invalid.", nameof(operation))
        };
        var request = new XElement(M + "UpdateInboxRules",
            new XElement(M + "MailboxSmtpAddress", normalizedMailbox),
            // Never remove Outlook's client-side rule blob. EWS defaults this to true.
            new XElement(M + "RemoveOutlookRuleBlob", "false"),
            new XElement(M + "Operations", mutation));
        var document = await SendAsync(normalizedMailbox, request, cancellationToken,
            responseValidator: ValidateMailboxSettingsResponse).ConfigureAwait(false);
        if (document.Descendants().Any(element => element.Name.LocalName is "RuleOperationError" or "Error"))
            throw new InvalidOperationException("Exchange rejected one or more Inbox rule operations.");
    }

    private static EwsOofSettings ParseOofSettings(XElement settings, string? allowExternalOof)
    {
        ValidateOofWireShape(settings);
        var state = settings.Element(T + "OofState")?.Value;
        var audience = settings.Element(T + "ExternalAudience")?.Value;
        if (state is not ("Disabled" or "Enabled" or "Scheduled") ||
            audience is not ("None" or "Known" or "All"))
            throw new InvalidOperationException("Exchange returned unsupported Out of Office settings.");
        var duration = settings.Element(T + "Duration");
        var internalReply = ReadOofReply(settings.Element(T + "InternalReply"));
        var externalReply = ReadOofReply(settings.Element(T + "ExternalReply"));
        var declineReply = ReadOofReply(settings.Element(T + "DeclineMeetingReply"));
        var parsed = new EwsOofSettings(state, audience,
            duration?.Element(T + "StartTime")?.Value,
            duration?.Element(T + "EndTime")?.Value,
            internalReply.Message,
            externalReply.Message,
            DeclineMeetingReply: declineReply.Present ? declineReply.Message : null,
            DeclineEventsForScheduledOof: ReadOptionalBoolean(settings.Element(T + "DeclineEventsForScheduledOOF"), "DeclineEventsForScheduledOOF"),
            DeclineAllEventsForScheduledOof: ReadOptionalBoolean(settings.Element(T + "DeclineAllEventsForScheduledOOF"), "DeclineAllEventsForScheduledOOF"),
            CreateOofEvent: ReadOptionalBoolean(settings.Element(T + "CreateOOFEvent"), "CreateOOFEvent"),
            OofEventSubject: settings.Element(T + "OOFEventSubject")?.Value,
            AutoDeclineFutureRequestsWhenOof: ReadOptionalBoolean(settings.Element(T + "AutoDeclineFutureRequestsWhenOOF"), "AutoDeclineFutureRequestsWhenOOF"),
            OofEventId: settings.Element(T + "OOFEventID")?.Value,
            EventsToDeleteIdsXml: settings.Element(T + "EventsToDeleteIDs")?.ToString(SaveOptions.DisableFormatting),
            AllowExternalOof: allowExternalOof,
            InternalReplyLanguage: internalReply.Language,
            ExternalReplyLanguage: externalReply.Language,
            DeclineMeetingReplyLanguage: declineReply.Language,
            InternalReplyPresent: internalReply.Present,
            ExternalReplyPresent: externalReply.Present,
            DeclineMeetingReplyPresent: declineReply.Present,
            RawSettingsXml: settings.ToString(SaveOptions.DisableFormatting));
        ValidateOofSettings(parsed);
        return parsed with { Revision = OofRevision(parsed) };
    }

    private static (string Message, string? Language, bool Present) ReadOofReply(XElement? reply)
    {
        if (reply is null) return (string.Empty, null, false);
        if (reply.Attributes().Any(attribute => !attribute.IsNamespaceDeclaration
            && attribute.Name != XNamespace.Xml + "lang")
            || reply.Elements().Any(element => element.Name != T + "Message")
            || reply.Elements(T + "Message").Count() > 1)
            throw new InvalidOperationException("Exchange returned an unsupported OOF reply shape.");
        var message = reply.Element(T + "Message");
        if (message?.Attributes().Any(attribute => !attribute.IsNamespaceDeclaration) == true
            || message?.Elements().Any() == true)
            throw new InvalidOperationException("Exchange returned an unsupported OOF reply shape.");
        var value = message?.Value ?? string.Empty;
        ValidateOofMessage(value, nameof(reply));
        var language = (string?)reply.Attribute(XNamespace.Xml + "lang");
        ValidateOofLanguage(language, nameof(reply));
        return (value, language, true);
    }

    private static void ValidateOofSettings(EwsOofSettings settings)
    {
        if (settings.State is not ("Disabled" or "Enabled" or "Scheduled"))
            throw new ArgumentException("OOF state must be Disabled, Enabled or Scheduled.", nameof(settings));
        if (settings.ExternalAudience is not ("None" or "Known" or "All"))
            throw new ArgumentException("External audience must be None, Known or All.", nameof(settings));
        ValidateOofMessage(settings.InternalReply, nameof(settings.InternalReply));
        ValidateOofMessage(settings.ExternalReply, nameof(settings.ExternalReply));
        ValidateOofMessage(settings.DeclineMeetingReply ?? string.Empty, nameof(settings.DeclineMeetingReply));
        ValidateOofLanguage(settings.InternalReplyLanguage, nameof(settings.InternalReplyLanguage));
        ValidateOofLanguage(settings.ExternalReplyLanguage, nameof(settings.ExternalReplyLanguage));
        ValidateOofLanguage(settings.DeclineMeetingReplyLanguage, nameof(settings.DeclineMeetingReplyLanguage));
        if (!settings.InternalReplyPresent && (settings.InternalReplyLanguage is not null || settings.InternalReply.Length > 0))
            throw new ArgumentException("An absent internal OOF reply cannot carry a message or language.", nameof(settings));
        if (!settings.ExternalReplyPresent && (settings.ExternalReplyLanguage is not null || settings.ExternalReply.Length > 0))
            throw new ArgumentException("An absent external OOF reply cannot carry a message or language.", nameof(settings));
        if (!settings.DeclineMeetingReplyPresent && (settings.DeclineMeetingReply is not null || settings.DeclineMeetingReplyLanguage is not null))
            throw new ArgumentException("An absent decline-meeting OOF reply cannot carry a message or language.", nameof(settings));
        _ = ParseEventsToDeleteIds(settings.EventsToDeleteIdsXml);
        if (settings.OofEventSubject is not null && (settings.OofEventSubject.Length > MaxOofMessageLength
            || settings.OofEventSubject.Any(character => character < '\u0020' && character is not ('\t' or '\r' or '\n'))))
            throw new ArgumentException("The OOF event subject is invalid.", nameof(settings.OofEventSubject));
        if (settings.OofEventId is not null && (settings.OofEventId.Length > MaxOofMessageLength
            || settings.OofEventId.Any(char.IsControl)))
            throw new ArgumentException("The OOF event ID is invalid.", nameof(settings.OofEventId));
        if (settings.State == "Scheduled" && (settings.StartTime is null || settings.EndTime is null))
            throw new ArgumentException("Scheduled OOF requires both startTime and endTime.", nameof(settings));
        if ((settings.StartTime is null) != (settings.EndTime is null))
            throw new ArgumentException("OOF startTime and endTime must be supplied together.", nameof(settings));
        if (settings.StartTime is not null &&
            (!TryParseOofTime(settings.StartTime, out var start)
             || !TryParseOofTime(settings.EndTime!, out var end)
             || start >= end))
            throw new ArgumentException("OOF startTime and endTime must be ISO timestamps with an explicit offset, with startTime before endTime.", nameof(settings));
    }

    private static void ValidateOofWireShape(XElement settings)
    {
        if (settings.Name != T + "OofSettings"
            || settings.Attributes().Any(attribute => !attribute.IsNamespaceDeclaration))
            throw new InvalidOperationException("Exchange returned an unsupported OOF settings shape.");
        var known = new HashSet<XName>
        {
            T + "OofState", T + "ExternalAudience", T + "Duration", T + "InternalReply",
            T + "ExternalReply", T + "DeclineMeetingReply", T + "DeclineEventsForScheduledOOF",
            T + "DeclineAllEventsForScheduledOOF", T + "CreateOOFEvent", T + "OOFEventSubject",
            T + "AutoDeclineFutureRequestsWhenOOF", T + "OOFEventID", T + "EventsToDeleteIDs"
        };
        if (settings.Elements().Any(element => !known.Contains(element.Name))
            || known.Any(name => settings.Elements(name).Count() > 1))
            throw new InvalidOperationException("Exchange returned unsupported or duplicate OOF settings fields.");
        var duration = settings.Element(T + "Duration");
        if (duration is not null && (duration.Attributes().Any(attribute => !attribute.IsNamespaceDeclaration)
            || duration.Elements().Any(element => element.Name != T + "StartTime" && element.Name != T + "EndTime")
            || duration.Elements(T + "StartTime").Count() > 1
            || duration.Elements(T + "EndTime").Count() > 1
            || duration.Elements().Any(element => element.Attributes().Any(attribute => !attribute.IsNamespaceDeclaration)
                || element.Elements().Any())))
            throw new InvalidOperationException("Exchange returned an unsupported OOF duration shape.");
        foreach (var name in new[] { "OofState", "ExternalAudience", "DeclineEventsForScheduledOOF",
            "DeclineAllEventsForScheduledOOF", "CreateOOFEvent", "OOFEventSubject", "AutoDeclineFutureRequestsWhenOOF", "OOFEventID" })
        {
            var element = settings.Element(T + name);
            if (element is not null && (element.Attributes().Any(attribute => !attribute.IsNamespaceDeclaration)
                || element.Elements().Any()))
                throw new InvalidOperationException("Exchange returned an unsupported OOF scalar field shape.");
        }
    }

    private static XElement? BuildOofReply(string name, bool present, string value, string? language)
    {
        if (!present) return null;
        var reply = new XElement(T + name, new XElement(T + "Message", value));
        if (language is not null) reply.SetAttributeValue(XNamespace.Xml + "lang", language);
        return reply;
    }

    private static XElement? ParseEventsToDeleteIds(string? xml)
    {
        // Exchange may return an empty optional collection. Treat it as omitted so a
        // read/merge does not manufacture an empty destructive field on the next write.
        if (string.IsNullOrWhiteSpace(xml)) return null;
        try
        {
            var element = XElement.Parse(xml, LoadOptions.PreserveWhitespace);
            if (element.Name != T + "EventsToDeleteIDs")
                throw new InvalidOperationException("Exchange returned an invalid EventsToDeleteIDs field.");
            if (element.Attributes().Any(attribute => !attribute.IsNamespaceDeclaration)
                || element.Elements().Any(child => child.Name != T + "EventToDeleteID"
                || child.Attributes().Any(attribute => !attribute.IsNamespaceDeclaration) || child.Elements().Any()))
                throw new InvalidOperationException("Exchange returned an invalid EventsToDeleteIDs field.");
            if (!element.Elements().Any()) return null;
            return element;
        }
        catch (XmlException exception)
        {
            throw new InvalidOperationException("Exchange returned an invalid EventsToDeleteIDs field.", exception);
        }
    }

    private static bool? ReadOptionalBoolean(XElement? element, string name) => element is null ? null
        : bool.TryParse(element.Value, out var value) ? value
        : throw new InvalidOperationException($"Exchange returned an invalid OOF {name} value.");

    private static void ValidateOofLanguage(string? language, string parameterName)
    {
        if (language is not null && (language.Length > 128 || language.Any(char.IsControl)))
            throw new ArgumentException("The OOF reply language is invalid.", parameterName);
    }

    private static bool TryParseOofTime(string value, out DateTimeOffset parsed)
    {
        parsed = default;
        if (value.Length is < 20 or > 64)
            return false;
        var hasExplicitOffset = value.EndsWith("Z", StringComparison.Ordinal)
            || (value.Length >= 6 && (value[^6] is '+' or '-') && value[^3] == ':'
                && char.IsDigit(value[^5]) && char.IsDigit(value[^4])
                && char.IsDigit(value[^2]) && char.IsDigit(value[^1]));
        if (!hasExplicitOffset)
            return false;
        return DateTimeOffset.TryParseExact(value,
            ["yyyy-MM-dd'T'HH:mm:sszzz", "yyyy-MM-dd'T'HH:mm:ss.FFFFFFFzzz",
             "yyyy-MM-dd'T'HH:mm:ss'Z'", "yyyy-MM-dd'T'HH:mm:ss.FFFFFFF'Z'"],
            CultureInfo.InvariantCulture,
            DateTimeStyles.AssumeUniversal | DateTimeStyles.AdjustToUniversal,
            out parsed);
    }

    private static void ValidateOofMessage(string value, string parameterName)
    {
        if (value is null || value.Length > MaxOofMessageLength
            || value.Any(character => character < '\u0020' && character is not ('\t' or '\r' or '\n')))
            throw new ArgumentException("The OOF message is too long or contains control characters.", parameterName);
    }

    private static string OofRevision(EwsOofSettings settings) => Convert.ToHexString(SHA256.HashData(
        JsonSerializer.SerializeToUtf8Bytes(new
        {
            settings.State,
            settings.ExternalAudience,
            settings.StartTime,
            settings.EndTime,
            settings.InternalReply,
            settings.ExternalReply,
            settings.DeclineMeetingReply,
            settings.DeclineEventsForScheduledOof,
            settings.DeclineAllEventsForScheduledOof,
            settings.CreateOofEvent,
            settings.OofEventSubject,
            settings.AutoDeclineFutureRequestsWhenOof,
            settings.OofEventId,
            settings.EventsToDeleteIdsXml,
            settings.AllowExternalOof,
            settings.InternalReplyLanguage,
            settings.ExternalReplyLanguage,
            settings.DeclineMeetingReplyLanguage,
            settings.InternalReplyPresent,
            settings.ExternalReplyPresent,
            settings.DeclineMeetingReplyPresent,
            settings.RawSettingsXml
        })));

    private static EwsInboxRule ParseInboxRule(XElement rule)
    {
        var id = rule.Element(T + "RuleId")?.Value;
        if (string.IsNullOrWhiteSpace(id)) throw new InvalidOperationException("Exchange returned an Inbox rule without an identifier.");
        var conditions = rule.Element(T + "Conditions");
        var exceptions = rule.Element(T + "Exceptions");
        var actions = rule.Element(T + "Actions");
        var unsupportedRuleFields = rule.Elements().Where(element => element.Name.Namespace != T || element.Name.LocalName is not
                ("RuleId" or "DisplayName" or "Priority" or "IsEnabled" or "Conditions" or "Exceptions"
                or "Actions" or "IsInError" or "IsNotSupported"))
            .Select(element => "RuleField:" + element.Name.LocalName);
        var ruleFieldNames = new[] { "RuleId", "DisplayName", "Priority", "IsEnabled", "Conditions", "Exceptions",
            "Actions", "IsInError", "IsNotSupported" };
        unsupportedRuleFields = unsupportedRuleFields.Concat(ruleFieldNames
            .Where(name => rule.Elements(T + name).Skip(1).Any())
            .Select(name => "RuleField:" + name + "Duplicate"));
        var unsupportedActions = actions?.Elements().Where(element => element.Name.Namespace != T || element.Name.LocalName is not
                ("MoveToFolder" or "CopyToFolder" or "MarkAsRead" or "AssignCategories" or "StopProcessingRules"))
            .Select(element => element.Name.LocalName).Distinct(StringComparer.Ordinal).ToList()
            ?? [];
        foreach (var name in new[] { "MoveToFolder", "CopyToFolder", "MarkAsRead", "AssignCategories", "StopProcessingRules" })
        {
            if (actions?.Elements(T + name).Skip(1).Any() == true)
                unsupportedActions.Add(name + "Duplicate");
        }
        var unsupportedConditions = conditions?.Elements().Where(element => element.Name.Namespace != T || element.Name.LocalName is not
                ("ContainsSubjectStrings" or "ContainsBodyStrings" or "FromAddresses" or "SentToAddresses"))
            .Select(element => element.Name.LocalName).Distinct(StringComparer.Ordinal).ToList()
            ?? [];
        foreach (var name in new[] { "ContainsSubjectStrings", "ContainsBodyStrings", "FromAddresses", "SentToAddresses" })
        {
            if (conditions?.Elements(T + name).Skip(1).Any() == true)
                unsupportedConditions.Add(name + "Duplicate");
        }
        var unsupportedExceptions = exceptions?.Elements().Select(element => element.Name.LocalName)
            .Distinct(StringComparer.Ordinal).ToArray() ?? Array.Empty<string>();
        var moveToFolder = ParseFolderTarget(actions?.Element(T + "MoveToFolder"), "MoveToFolder", unsupportedActions);
        var copyToFolder = ParseFolderTarget(actions?.Element(T + "CopyToFolder"), "CopyToFolder", unsupportedActions);
        var isInError = ReadRuleBoolean(rule.Element(T + "IsInError"), "IsInError");
        var isNotSupported = ReadRuleBoolean(rule.Element(T + "IsNotSupported"), "IsNotSupported");
        return new EwsInboxRule(id,
            rule.Element(T + "DisplayName")?.Value ?? string.Empty,
            ParsePositiveInt(rule.Element(T + "Priority"), "Priority"),
            ReadRequiredRuleBoolean(rule.Element(T + "IsEnabled"), "IsEnabled"),
            new EwsRulePredicates(
                Strings(conditions?.Element(T + "ContainsSubjectStrings")),
                Strings(conditions?.Element(T + "ContainsBodyStrings")),
                Addresses(conditions?.Element(T + "FromAddresses"), "FromAddresses", unsupportedConditions),
                Addresses(conditions?.Element(T + "SentToAddresses"), "SentToAddresses", unsupportedConditions)),
            new EwsRuleActions(
                moveToFolder,
                copyToFolder,
                Bool(actions?.Element(T + "MarkAsRead")),
                Strings(actions?.Element(T + "AssignCategories")),
                ReadRuleBoolean(actions?.Element(T + "StopProcessingRules"), "StopProcessingRules")),
            unsupportedActions.Concat(unsupportedRuleFields).Distinct(StringComparer.Ordinal).ToArray(),
            unsupportedConditions.Distinct(StringComparer.Ordinal).ToArray(), unsupportedExceptions, isInError, isNotSupported);
    }

    private static XElement BuildRule(EwsInboxRule rule, bool includeId)
    {
        ValidateRule(rule);
        return new XElement(T + "Rule",
            includeId ? new XElement(T + "RuleId", rule.Id) : null,
            new XElement(T + "DisplayName", rule.DisplayName),
            new XElement(T + "Priority", rule.Priority.ToString(CultureInfo.InvariantCulture)),
            new XElement(T + "IsEnabled", rule.IsEnabled.ToString().ToLowerInvariant()),
            BuildPredicates(rule.Conditions),
            new XElement(T + "Exceptions"),
            BuildActions(rule.Actions));
    }

    private static XElement BuildPredicates(EwsRulePredicates predicates)
    {
        var conditions = new XElement(T + "Conditions");
        AddStrings(conditions, "ContainsBodyStrings", predicates.ContainsBodyStrings);
        AddStrings(conditions, "ContainsSubjectStrings", predicates.ContainsSubjectStrings);
        AddAddresses(conditions, "FromAddresses", predicates.FromAddresses);
        AddAddresses(conditions, "SentToAddresses", predicates.SentToAddresses);
        return conditions;
    }

    private static XElement BuildActions(EwsRuleActions actions)
    {
        var result = new XElement(T + "Actions");
        AddStrings(result, "AssignCategories", actions.Categories);
        AddFolderAction(result, "CopyToFolder", actions.CopyToFolder);
        if (actions.MarkAsRead is { } markAsRead)
            result.Add(new XElement(T + "MarkAsRead", markAsRead.ToString().ToLowerInvariant()));
        AddFolderAction(result, "MoveToFolder", actions.MoveToFolder);
        if (actions.StopProcessingRules) result.Add(new XElement(T + "StopProcessingRules", "true"));
        return result;
    }

    private static void ValidateRule(EwsInboxRule rule)
    {
        if (string.IsNullOrWhiteSpace(rule.DisplayName) || rule.DisplayName.Length > 255 || rule.DisplayName.Any(char.IsControl))
            throw new ArgumentException("Inbox rule displayName must contain 1–255 characters without control characters.");
        if (rule.Priority is < 1 or > 10_000) throw new ArgumentException("Inbox rule priority is outside the supported range.");
        if (rule.UnsupportedActions.Count > 0 || rule.UnsupportedConditions.Count > 0
            || rule.UnsupportedExceptions.Count > 0 || rule.IsInError || rule.IsNotSupported)
            throw new ArgumentException("This rule contains an unsupported action and cannot be safely rewritten.");
        var predicates = rule.Conditions;
        var predicateCount = predicates.ContainsSubjectStrings.Count + predicates.ContainsBodyStrings.Count
            + predicates.FromAddresses.Count + predicates.SentToAddresses.Count;
        if (predicateCount == 0) throw new ArgumentException("An Inbox rule needs at least one supported condition.");
        ValidateRuleStrings(predicates.ContainsSubjectStrings, "subject condition");
        ValidateRuleStrings(predicates.ContainsBodyStrings, "body condition");
        ValidateAddresses(predicates.FromAddresses);
        ValidateAddresses(predicates.SentToAddresses);
        ValidateRuleStrings(rule.Actions.Categories, "category action");
        if (rule.Actions.MoveToFolder is null && rule.Actions.CopyToFolder is null
            && rule.Actions.MarkAsRead is null && rule.Actions.Categories.Count == 0 && !rule.Actions.StopProcessingRules)
            throw new ArgumentException("An Inbox rule needs at least one supported action.");
    }

    private static void ValidateRuleStrings(IReadOnlyList<string> values, string description)
    {
        if (values.Count > MaxRuleStrings || values.Any(value => string.IsNullOrWhiteSpace(value) || value.Length > 255 || value.Any(char.IsControl)))
            throw new ArgumentException($"The Inbox rule {description} list is invalid.");
    }

    private static void ValidateAddresses(IReadOnlyList<string> values)
    {
        if (values.Count > MaxRuleStrings) throw new ArgumentException("The Inbox rule address list is too long.");
        foreach (var value in values) _ = NormalizeAddress(value);
    }

    private static void AddStrings(XElement parent, string name, IReadOnlyList<string> values)
    {
        if (values.Count == 0) return;
        parent.Add(new XElement(T + name, values.Select(value => new XElement(T + "String", value))));
    }

    private static void AddAddresses(XElement parent, string name, IReadOnlyList<string> values)
    {
        if (values.Count == 0) return;
        parent.Add(new XElement(T + name, values.Select(value =>
            new XElement(T + "Address", new XElement(T + "EmailAddress", NormalizeAddress(value))))));
    }

    private static void AddFolderAction(XElement parent, string name, string? folder)
    {
        if (folder is null) return;
        var reference = folder.StartsWith(OpaqueFolderTargetPrefix, StringComparison.Ordinal)
            ? new XElement(T + "FolderId", new XAttribute("Id", folder[OpaqueFolderTargetPrefix.Length..]))
            : RuleDistinguishedFolderIds.Contains(folder)
                ? new XElement(T + "DistinguishedFolderId", new XAttribute("Id", folder))
            : FolderReference(folder);
        parent.Add(new XElement(T + name, reference));
    }

    private static IReadOnlyList<string> Strings(XElement? parent)
    {
        if (parent is null) return [];
        if (parent.Attributes().Any(attribute => !attribute.IsNamespaceDeclaration)
            || parent.Elements().Any(element => element.Name != T + "String"
            || element.Attributes().Any(attribute => !attribute.IsNamespaceDeclaration) || element.Elements().Any()))
            throw new InvalidOperationException("Exchange returned an unsupported Inbox rule string-list shape.");
        var elements = parent.Elements(T + "String").ToArray();
        if (elements.Length > MaxRuleStrings)
            throw new InvalidOperationException("Exchange returned too many Inbox rule strings.");
        return elements.Select(element => element.Value).Where(value => value.Length > 0).ToArray();
    }

    private static IReadOnlyList<string> Addresses(XElement? parent, string fieldName,
        ICollection<string> unsupportedConditions)
    {
        if (parent is null) return [];
        if (parent.Attributes().Any(attribute => !attribute.IsNamespaceDeclaration)
            || parent.Nodes().OfType<XText>().Any(text => !string.IsNullOrWhiteSpace(text.Value))
            || parent.Elements().Any(element => element.Name != T + "Address"
            || element.Attributes().Any(attribute => !attribute.IsNamespaceDeclaration)
            || element.Nodes().OfType<XText>().Any(text => !string.IsNullOrWhiteSpace(text.Value))))
            throw new InvalidOperationException("Exchange returned an unsupported Inbox rule address-list shape.");
        var elements = parent.Elements(T + "Address").ToArray();
        if (elements.Length > MaxRuleStrings)
            throw new InvalidOperationException("Exchange returned too many Inbox rule addresses.");
        var values = new List<string>(elements.Length);
        foreach (var address in elements)
        {
            var children = address.Elements().ToArray();
            var seen = new HashSet<XName>();
            var lastPosition = -1;
            var rewritable = true;
            string? emailAddress = null;
            string? routingType = null;
            foreach (var child in children)
            {
                var position = child.Name == T + "Name" ? 0
                    : child.Name == T + "EmailAddress" ? 1
                    : child.Name == T + "RoutingType" ? 2
                    : child.Name == T + "MailboxType" ? 3
                    : child.Name == T + "ItemId" ? 4
                    : child.Name == T + "OriginalDisplayName" ? 5 : -1;
                if (position < 0 || !seen.Add(child.Name) || position <= lastPosition)
                    throw new InvalidOperationException("Exchange returned an unsupported Inbox rule address-list shape.");
                lastPosition = position;

                if (child.Name == T + "ItemId")
                {
                    if (child.Elements().Any()
                        || child.Nodes().OfType<XText>().Any(text => !string.IsNullOrWhiteSpace(text.Value))
                        || child.Attribute("Id") is null
                        || string.IsNullOrWhiteSpace((string?)child.Attribute("Id"))
                        || child.Attributes().Any(attribute => !attribute.IsNamespaceDeclaration
                            && (attribute.Name.Namespace != XNamespace.None
                                || attribute.Name.LocalName is not ("Id" or "ChangeKey"))))
                        throw new InvalidOperationException("Exchange returned an unsupported Inbox rule address-list shape.");
                    rewritable = false;
                    continue;
                }

                if (child.Attributes().Any(attribute => !attribute.IsNamespaceDeclaration) || child.Elements().Any())
                    throw new InvalidOperationException("Exchange returned an unsupported Inbox rule address-list shape.");
                switch (child.Name.LocalName)
                {
                    case "EmailAddress":
                        if (child.Value.Length == 0) throw new InvalidOperationException("Exchange returned an unsupported Inbox rule address-list shape.");
                        emailAddress = child.Value;
                        break;
                    case "RoutingType":
                        if (child.Value.Length == 0) throw new InvalidOperationException("Exchange returned an unsupported Inbox rule address-list shape.");
                        routingType = child.Value;
                        if (!string.Equals(routingType, "SMTP", StringComparison.OrdinalIgnoreCase)) rewritable = false;
                        break;
                    case "MailboxType":
                        if (child.Value is not ("Unknown" or "OneOff" or "Mailbox" or "PublicDL" or "PrivateDL"
                            or "Contact" or "PublicFolder" or "GroupMailbox" or "ImplicitContact"))
                            throw new InvalidOperationException("Exchange returned an unsupported Inbox rule address-list shape.");
                        rewritable = false;
                        break;
                    case "Name":
                    case "OriginalDisplayName":
                        rewritable = false;
                        break;
                }
            }

            if (emailAddress is null)
            {
                rewritable = false;
            }
            else if (routingType is null || string.Equals(routingType, "SMTP", StringComparison.OrdinalIgnoreCase))
            {
                try { _ = NormalizeAddress(emailAddress); }
                catch (ArgumentException) { rewritable = false; }
            }
            values.Add(emailAddress ?? string.Empty);
            if (!rewritable && !unsupportedConditions.Any(value => string.Equals(value, fieldName + "Metadata", StringComparison.Ordinal)))
                unsupportedConditions.Add(fieldName + "Metadata");
        }
        return values.Where(value => value.Length > 0).ToArray();
    }

    private static string? ParseFolderTarget(XElement? action, string actionName, ICollection<string> unsupportedActions)
    {
        if (action is null) return null;
        var children = action.Elements().ToArray();
        var supportedChild = children.Length == 1
            && (children[0].Name == T + "FolderId" || children[0].Name == T + "DistinguishedFolderId");
        if (action.Attributes().Any(attribute => !attribute.IsNamespaceDeclaration) || !supportedChild)
        {
            unsupportedActions.Add(actionName + "Target");
            return OpaqueFolderTargetPrefix;
        }
        var child = children[0];
        var id = (string?)child.Attribute("Id");
        if (string.IsNullOrWhiteSpace(id) || child.Elements().Any() || child.Attributes().Any(attribute =>
            !attribute.IsNamespaceDeclaration
            && (attribute.Name.LocalName != "Id" || attribute.Name.Namespace != XNamespace.None)))
        {
            unsupportedActions.Add(actionName + "Target");
            return OpaqueFolderTargetPrefix + (id ?? string.Empty);
        }
        if (child.Name == T + "DistinguishedFolderId")
        {
            if (!RuleDistinguishedFolderIds.Contains(id))
                unsupportedActions.Add(actionName + "Target");
            return RuleDistinguishedFolderIds.Contains(id) ? id : OpaqueFolderTargetPrefix + id;
        }
        return OpaqueFolderTargetPrefix + id;
    }

    private static bool? Bool(XElement? element) => element is null ? null
        : bool.TryParse(element.Value, out var value) ? value : throw new InvalidOperationException("Exchange returned an invalid Inbox rule boolean.");

    private static bool ReadRuleBoolean(XElement? element, string name) => element is null
        ? false
        : bool.TryParse(element.Value, out var value)
            ? value
            : throw new InvalidOperationException($"Exchange returned an invalid Inbox rule {name}.");

    private static bool ReadRequiredRuleBoolean(XElement? element, string name) => element is null
        ? throw new InvalidOperationException($"Exchange omitted Inbox rule {name}.")
        : ReadRuleBoolean(element, name);

    private static int ParsePositiveInt(XElement? element, string name) =>
        int.TryParse(element?.Value, NumberStyles.Integer, CultureInfo.InvariantCulture, out var value) && value > 0
            ? value : throw new InvalidOperationException($"Exchange returned an invalid Inbox rule {name}.");

    private static string Revision(bool? blob, XElement? inboxRules) =>
        Convert.ToHexString(SHA256.HashData(JsonSerializer.SerializeToUtf8Bytes(new
        {
            OutlookRuleBlobExists = blob.HasValue ? blob.Value ? "true" : "false" : "unavailable",
            InboxRulesPresent = inboxRules is not null,
            InboxRulesXml = inboxRules?.ToString(SaveOptions.DisableFormatting) ?? string.Empty
        })));

    private static void ValidateMailboxSettingsResponse(XDocument document, string operation)
    {
        var body = document.Root?.Name == Soap + "Envelope"
            ? document.Root.Element(Soap + "Body")
            : null;
        var responseName = operation switch
        {
            "GetUserOofSettingsRequest" => "GetUserOofSettingsResponse",
            "SetUserOofSettingsRequest" => "SetUserOofSettingsResponse",
            _ => operation + "Response"
        };
        var bodyElements = body?.Elements().ToArray() ?? [];
        var response = bodyElements.Length == 1 && bodyElements[0].Name == M + responseName
            ? bodyElements[0]
            : null;
        if (response is null || response.Name.Namespace != M || body?.Element(Soap + "Fault") is not null)
            throw new InvalidOperationException("Exchange returned an unsuccessful response.");

        // A response code/message from another namespace is not an EWS success signal.
        if (response.DescendantsAndSelf()
            .Where(element => element.Name.LocalName is "ResponseCode" or "ResponseMessage" or "ResponseMessages")
            .Any(element => element.Name.Namespace != M))
            throw new InvalidOperationException("Exchange returned an unsuccessful response.");

        var isRulesOperation = operation is "GetInboxRules" or "UpdateInboxRules";
        if (isRulesOperation)
        {
            if (!string.Equals((string?)response.Attribute("ResponseClass"), "Success", StringComparison.Ordinal))
                throw new InvalidOperationException("Exchange returned an unsuccessful Inbox rule response.");
            var directCodes = response.Elements(M + "ResponseCode").ToArray();
            if (directCodes.Length != 1 || directCodes[0].Value != "NoError"
                || response.Elements(M + "ResponseMessage").Any()
                || response.Elements(M + "ResponseMessages").Any())
                throw new InvalidOperationException("Exchange returned an unsuccessful Inbox rule response.");
            return;
        }

        var responseMessages = response.Elements(M + "ResponseMessage").ToArray();
        if (operation == "SetUserOofSettingsRequest" && responseMessages.Length == 0)
            throw new InvalidOperationException(
                "Exchange returned the schema-valid empty SetUserOofSettingsResponse without a ResponseMessage; the response carries no success evidence.");
        if (responseMessages.Length != 1 || response.Elements(M + "ResponseMessages").Any()
            || !string.Equals((string?)responseMessages[0].Attribute("ResponseClass"), "Success", StringComparison.Ordinal))
            throw new InvalidOperationException("Exchange returned an unsuccessful OOF response.");
        var oofCodes = responseMessages[0].Elements(M + "ResponseCode").ToArray();
        if (oofCodes.Length != 1 || oofCodes[0].Value != "NoError")
            throw new InvalidOperationException("Exchange returned an unsuccessful OOF response.");
    }
}
