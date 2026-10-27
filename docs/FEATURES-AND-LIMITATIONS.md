# Features, workflows and limitations

This is the implementation contract for Exchange MCP 1.16.8. Discover the current MCP catalog and read `mail_profile` before acting; a tool can still be unavailable to a particular host, scope, mailbox or current permission set. Source support, synthetic checks, deployed code, actual Exchange success and host/user-visible behavior are separate evidence levels.

## Identity and mailbox selection

`mail_profile` identifies `actorMailbox`, effective `mailbox` and `delegated`, along with setup/usage guidance. Omit `mailboxHandle` for the actor's own mailbox. For another mailbox, call `mail_list_mailboxes`, continue its bounded scan as needed, then pass the returned opaque `mailboxHandle` to each selected call. Selection applies to that call only; it does not become sticky. No token email field, arbitrary SMTP argument or per-user target mapping chooses a delegated mailbox.

Read `candidateCount`, `scannedCount`, `catalogScanComplete`, `complete`, `permissionCheckFailures`, `incompleteFolderTargets`, `capacityLimited` and `catalogFailures`. Catalog completion describes a bounded candidate set; it is not an exhaustive or future entitlement guarantee. Folder summaries contain up to eight default folders or the first custom folder when no defaults are visible, not the full hierarchy. A selected `mail_list_folders` refuses to present an incomplete delegated listing as complete.

Discovery uses validated LDAP User, Shared, Room and Equipment mailbox metadata, current directory delegation evidence and native folder rights. Metadata-only owner hierarchy reads strip owner rights and do not expose content. Each selected call freshly checks actor/target GUID and canonical primary SMTP plus the relevant rights. Directory metadata is not a permission grant. Unknown rights stay unknown: verified read access can coexist with unknown Send As, and Full Access does not imply Send As, Send on Behalf or mailbox administration. `mail_get_mailbox_access` reports these decisions separately. Exchange remains authoritative.

Ordinary handles expire after 15 minutes and bind actor, mailbox, client, OAuth session, item kind and change key as applicable. Use returned refreshed handles after every modification. Cross-mailbox/cross-kind/stale handles are refused. Recall-report handles and own-Inbox event read references have separate 48-hour lives. Restart behavior is described in [deployment](DEPLOYMENT.md).

## Mail and draft workflow

| Purpose | Tools / behavior |
| --- | --- |
| Discover/read | `mail_list_folders`, `mail_search`, `mail_read` |
| Compose | `mail_create_draft`, native `mail_reply_draft`, native `mail_forward_draft`, `mail_edit_draft` |
| Review/send | `mail_preview_draft`, `mail_send_draft`; optional `mail_review_email` view |
| Organize | `mail_mark_read`, `mail_set_categories`, `mail_move`, `mail_delete` |
| Folder maintenance | `mail_create_folder`, `mail_rename_folder`, `mail_delete_folder`; protected/system/non-empty constraints remain |
| Attachments | `mail_list_attachments`, `mail_read_attachment`, `mail_create_attachment`, `mail_delete_attachment` |

For a new message, provide only the authored body and explicit To/Cc/Bcc. For a reply or forward, resolve the exact original message and use its fresh `mail_read` handle. A native reply retains its relationship, subject and quoted history. `replyAll` requires the user's intent. A new draft with an `RE:` subject is not a native reply.

Use `bodyType=HTML` for formatted content, Persian RTL, tables/images and when appropriate to the HTML original. `bodyType` describes authored syntax; a validated native HTML original can remain HTML even when authored content is Text. The server escapes that authored Text, preserves the native quotation/CID images and adds the saved signature before the quote. Never reconstruct source HTML or images through the model. Native header formatting uses original From/Sender/recipient properties and the actual sent timestamp in the mailbox timezone where available.

Draft creation automatically applies the selected mailbox's saved default/use-rule profile. `signatureName` chooses an existing profile; `includeSignature=false` explicitly omits it. Inspect `signatureStatus`, warnings and `readyToSend`. A retained `draft_incomplete` or uncertain signature result is an existing unsent draft to inspect, not a reason to create another reply or silently send unsigned.

Preview after the final body, signature, recipient or attachment change. The inline review shows the effective From, To/Cc/Bcc, subject, body, images and attachment names. Edit uses current revision/permission guards; Don't send closes the review and leaves the draft unsent. No opening action sends. The server never automatically retries an uncertain send. Mail/item deletion uses MoveToDeletedItems, not a recipient recall mechanism.

Per-file attachment limit is 5 MiB; an item is bounded to 10 MiB and 100 attachments, including embedded items. Inline images must be PNG/JPEG/GIF with validated headers and CID bindings; ordinary files remain ordinary attachments. Attachment writes return refreshed item handles. These bounds do not guarantee antivirus scanning or delivery through downstream transport size policies. HTTP requests are limited to 8 MiB and EWS responses to at most 16 MiB.

## Approval, submission and uncertainty

The agent must have the user's instruction/approval for consequential actions. The server also enforces operation-specific native approval, current rights, feature gates, recipient policy, exact content/revision and durable single-attempt reservation.

- Ordinary `mail_send_draft` for exact OAuth client `https://chatgpt.com/oauth/client.json` uses `mail.send` plus the host's normal tool approval, without a second MCP confirmation form. Consent is a permission grant, not a user's instruction to send arbitrary mail.
- Other clients use native form approval on a stateful or MRTR-capable connection unless the server verifies an explicitly configured standing policy.
- That standing policy is disabled by default. It names one GUID-enrolled actor, exactly two mailboxes including the actor, and one or two existing allowed OAuth clients. Acting mailbox and every To/Cc/Bcc recipient must belong to that exact pair. It grants no access and does not bypass current sender rights, recipient policy, revision or replay checks. Existing approval continuations cannot become preapproved sends.
- Native recall can use that same exact standing-policy boundary; the ordinary ChatGPT OAuth send exception does not authorize recall. Meetings, task communications and access changes retain their own guarded approval paths.

Approval is bound to actor, mailbox, client/session, current item/change key and exact operation content for up to 15 minutes, then consumed before dispatch. A decline cancels the operation. An expired/changed approval needs a fresh read and review. The private replay store survives replacement and keeps uncertain attempt holds; never remove state to force a retry.

| Tracking send status | Meaning / required response |
| --- | --- |
| `not_dispatched` | This invocation did not attempt EWS SendItem; it says nothing about an earlier invocation |
| `rejected` | Exchange explicitly refused the submission |
| `unknown` | Dispatch may have completed; reconcile Drafts/Sent/Inbox before considering another attempt |
| `acknowledged` | Exchange accepted submission; delivery and recipient processing are separate |

Each HTTP request has a server-generated `X-Request-ID`; tool results carry the same tracking ID and EWS receives it as `client-request-id`. A host error without that ID does not prove the call reached this service. Preserve the time/tool/ID and reconcile uncertain writes read-only. Rate/capacity errors include `reason`, `retrySeconds` and `dispatchStatus=not_dispatched`; they are not an OAuth reconnect request.

## Inline review and host limits

`mail_preview_draft`, signature capture/preview and `mail_preview_saved_signature` prefer inline MCP Apps presentation. For an ordinary request to display the saved signature, call `mail_preview_saved_signature {}`. It reads the saved new-message/reply default or sole profile and ignores pending edits without consuming/extending/restaging them. It does not save, alter defaults/setup or open a conversation panel.

`mail_review_email` and `mail_review_signature` are optional conversation entrypoints for an explicit user request. The email view reloads the last successfully reviewed exact reference for actor/mailbox/client/OAuth session, retained for 15 minutes. Several conversations may share that session, so inspect From/To/Cc/Bcc/subject; it is not a per-conversation draft selector. Empty, expired, changed or revoked references do not search Drafts or create a substitute. The signature view inspects pending or saved state without restaging or saving it.

Private email HTML and inline image bytes stay in component metadata. Static UI resources retain prior URI aliases. Unsupported native Office content can produce a disclosed sanitized text fallback with Send/Edit disabled; this does not rewrite the stored draft. A sendable preview may still be non-editable when the native source cannot safely round-trip through the compact editor.

Successful preview generation or `resources/read` proves that boundary only. It does not prove host registration, widget publication, display, pixel fidelity or the user's viewing. Cached resources may produce no new read. Explain a display limitation once, preserve the draft/profile, show the supported textual review and offer the optional conversation view if appropriate. Do not invent a publisher API, retry repeatedly, reconnect OAuth to refresh navigation or automatically open an extra panel after a successful inline preview.

## Signatures and first use

Profiles are stored in the mailbox's EWS UserConfiguration and are separate from Classic Outlook/OWA local signature settings. `mail_signatures` lists exact quotas and usage; `mail_save_signature`, `mail_delete_signature`, `mail_signature_defaults`, `mail_signature_rules` and `mail_apply_signature` maintain approved profiles/rules or apply one to a draft. Compose/application does not change saved defaults.

| Mailbox signature quota | Limit |
| --- | --- |
| Profiles | 10 |
| Use rules | 20 |
| Body per profile | 65,536 characters |
| Inline images per profile | 8 |
| Decoded size per image | 512 KiB |
| Decoded image total per mailbox | 2 MiB |
| Serialized UTF-8 configuration including base64 | 3 MiB |

A replacement of the same profile name uses its existing slot; no unrelated profile is evicted. Omitted image input when editing retains stored bytes; an explicit empty image list requests clearing and must still satisfy CID references. Revision and quota checks happen before the EWS write.

For source capture, resolve one selected email and call `mail_capture_signature`. It extracts only a safe selected fragment and its referenced inline PNG/JPEG/GIF bytes directly from Exchange; quoted history, remote resources and arbitrary attachments are excluded. Multiple/uncertain fragments require the user's selection. Safe table structure, direction and source formatting are retained; omitted passive formatting is disclosed. For pasted input use `mail_preview_signature`.

Show the supplied visual preview where supported, otherwise its exact text/layout/image summary and warnings. After explicit approval, `mail_commit_signature` consumes the same `previewHandle` once; do not reconstruct the candidate. The server binds actor/mailbox/client/session, saved revision, source message/change key and selected defaults. One candidate per actor/mailbox, 64 entries and 32 MiB total are retained in process memory for 15 minutes; expiry/restart requires a new capture. Remote URLs, active content, unsafe links, DTDs/deep nesting and invalid CID images remain refused. These controls are not an antivirus guarantee.

`mail_signature_test_draft` creates only a requested unsent test draft; it does not send or prove Outlook visual appearance. Pending previews are not saved profiles. Approval to inspect or test is not approval to replace a profile.

On first interactive use, ask فارسی / English and persist it before a bounded recent Sent signature search. Offer the first free profile slot, show the exact candidate, obtain save approval, ask about more profiles/rules and finish/skip only at the user's request. `mail_onboarding`, `mail_onboarding_update` and `mail_finish_onboarding` preserve existing signature state. Onboarding belongs to the actor's own mailbox even when a shared target is selected. Pending setup never blocks ordinary work; completed/skipped state stays quiet. Background events, healthy checks and token/subscription renewals do not initiate onboarding.

## Calendar and rooms

Tools include folder maintenance, `calendar_list_events`, `calendar_search`, `calendar_read_event`, `calendar_read_series`, event create/update/delete, `calendar_read_meeting_message`, `calendar_respond`, `calendar_move_event`, `calendar_copy_event` and `calendar_freebusy`. `calendar_list_room_lists`, `calendar_list_rooms` and `calendar_find_meeting_times` expose directory room discovery and bounded availability suggestions. Exchange resource-booking policy remains decisive.

List/search entries are summaries: `detailsComplete=false` and absent/null body, attendees or attachments mean not loaded, not empty. Read the actual event before reporting those details or attendee responses. `MeetingRequestWasSent` confirms an invitation, not acceptance. Use explicit time-zone offsets; an event that ends when another starts is not an overlap.

`calendar_update_event` patches only supplied fields, preserving omitted HTML, attendees/responses, disabled reminders, independent start/end time zones and recurrence. IANA IDs map to Exchange Windows IDs. XML Schema recurrence range dates retain their local calendar date, including optional timezone suffixes. Series reads expose first/last and modified/deleted occurrence metadata. Importance, response requested and proposal controls are supported. Create/update can stage an unsent meeting/series; an owned personal appointment may be converted to a meeting or recurring series.

Search returns bounded pages of stored events/recurring masters; it does not expand occurrences. Date-range views and series/occurrence reads have their own contracts. Move/copy accepts only owned personal appointments or complete personal series into an owned calendar within the selected mailbox. Meetings, attendee items, individual occurrences and cross-mailbox transfers are refused. Meeting creation approval is bound to its destination folder.

Meeting-message reads cover requests, responses and cancellations with associated event/proposed times. `calendar_respond` requires the explicit calendar/request source and occurrence/series scope. Safe Text/HTML comments are supported. `sendResponse=false` silently saves accept/tentative; decline requires native approval. A sent time proposal needs both times, `sendResponse=true`, Exchange support and a specific occurrence, not a recurring master. It does not reschedule the organizer.

Published attendee changes require organizer authority, `sendUpdates=true` and native approval. Invitations, updates, cancellations and responses retain exact approval/replay checks. Standard event/series deletion moves to Deleted Items; deleting an occurrence removes that date without promising a separately recoverable copy. A custom cancellation uses `CancelCalendarItem`; organizer-copy recovery is not guaranteed.

## Contacts, tasks and groupware attachments

`people_*` provides contact folders, personal contact/group list/search/read/create/update/delete and `people_resolve_directory`. Group membership changes use incremental native add/remove, preserving unrelated members. A directory lookup is not an access grant or exhaustive address-book export.

`task_*` provides task folders, list/search/read/create/update/complete/reopen/delete, dates, reminders, priority, categories, percent complete and bounded recurrence. Ordinary task editing refuses assigned copies so it cannot bypass native ownership/version/reporting.

For assignment, create an unassigned nonrecurring task, then call `task_assign`. Native `task_assignment_messages` / `task_read_assignment_message` distinguish actual task communications from ordinary report emails. `task_respond` accepts/declines, `task_update_assignment` reports progress/completion, `task_reassign` transfers an accepted task, and `task_process_update` applies a valid unprocessed response/update to an existing tracker. `task_assignment_status` separates acceptance from progress; `unknown` is not failure and `isProcessed=null` on a task does not mean an unprocessed request. Read the actual notice for that flag. Sending and agent-invoked local processing use exact native confirmation.

Native assignment preserves task IDs, versions, ownership, assigner chain, sender and fixed attachment snapshot. Each native action is capped at 512 KiB UTF-8 XML including metadata/base64, even when ordinary attachment quotas would allow more. Missing/mismatched identifiers, explicit zero versions and changed file bytes remain refused. Recipient Outlook can independently process notices; do not replay an already processed one. Arbitrary text-file byte normalization is not universally qualified.

`task_plan_assignments` previews a finite expansion of an unchanged unassigned template. `task_execute_assignment_plan` creates independent nonrecurring copies per person/date, each with a unique ID and own acceptance/progress state. Up to eight assignees and 32 total copies are supported, with explicit `throughDate` within 32 calendar years; exceeding the limit is refused, never truncated. Daily/weekly/monthly/yearly and relative monthly/yearly patterns are supported; completion-triggered regeneration cannot be expanded. One exact approval covers all copies/recipients/dates/reminders. Execution occurs during that call, stops at the first failure/uncertainty and reports remaining copies unsent; it does not schedule future background sends. Plans expire after five minutes/restart and are single use, with 1 MiB plan/template/confirmation payloads and a 128-plan / 16 MiB store.

`task_delete(scope="series")` can move the selected assigned task copy recoverably to Deleted Items after native confirmation. It sends no notice and leaves other mailboxes' copies/assignment intact.

`groupware_list_attachments`, `groupware_read_attachment`, `groupware_create_attachment` and `groupware_delete_attachment` cover typed calendar-event, contact and task attachments under existing current rights/handle checks. Limits are 5 MiB/file, 10 MiB and 100/item. Writes save only: organizer meeting attachment changes need a later approved `calendar_update_event(sendUpdates=true)` to transmit, even if no other field changes. Direct assigned-task attachment editing is refused.

## Mailbox settings, sharing and synchronization

`mail_oof` / `mail_set_oof` are own-mailbox-only automatic replies. Inbox rule read/create/update/delete supports the implemented native predicates/actions with validation and protected-rule/concurrency checks; do not treat it as a general Outlook rule import or a permission bypass. Selected targets require current appropriate rights.

`sharing_get_folder_permissions`, `sharing_set_folder_permission`, `sharing_remove_folder_permission` and `delegate_list` / add/update/remove expose native ACL/delegate administration only when authorized. Such a call can change real access; a release deployment itself does not grant rights. Exact approval discloses native Send on Behalf effects and mailbox-wide private-item access. Delegate writes verify the complete post-write list, all six folder levels, flags, meeting delivery and unrelated entries. Acknowledged writes may use one bounded read-only settling retry for the explicitly supported Exchange transient responses; the mutation is never repeated. An incomplete verification is uncertain. A fully verified removal releases held add/update records for that same principal/mailbox, without resetting other holds.

`mail_sync_folders` / `mail_sync_items` provide bounded Exchange sync pages and opaque mailbox-bound cursors. They are change feeds for callers that implement their own reconciliation, not an archive backup, a durable cross-mailbox cursor or automatic mailbox mirroring.

## Incoming mail and background processing

`email.received` is a host-managed own-Inbox event on MCP protocol `2026-07-28`. `mail_event_status` reads subscription state and does not subscribe. A supporting host owns discovery, verified callback/signing keys, subscription, renewal and event delivery to its agent. Employees do not supply callback URLs/secrets or install timers.

The server baselines before reporting arrivals, uses EWS streaming and reconciles on actual events/recovery; it does not periodically poll the Inbox. It sends minimal sender/subject/received time, recipient role (`to`, `cc`, `unknown`) and an opaque message reference, not full bodies or attachments. Queues/subscriptions and lifetime are bounded; truncation/recovery gaps must be disclosed. Default requested lifetime is 24 hours, maximum seven days, and effective expiry never exceeds the authenticating token. The host renews through normal OAuth without storing OAuth tokens in the worker.

The event read reference is valid 48 hours from observation and accepted only by `mail_read` for the own mailbox. A moved item can be recovered through bounded exact SearchKey matching; ambiguous, incomplete or unavailable recovery is refused. A successful read returns a fresh ordinary handle. Older already-created events retain their original expiry.

Server observation, durable queueing, callback 2xx, host execution, agent awareness and visible notification are separate. A host may batch/delay work. No immediate execution or announcement time is guaranteed. Deduplicate stable event IDs and honor silent-awareness/actionable-notification preferences. Background events never authorize writes or trigger onboarding. Without host event support, offer an on-demand check; do not silently install polling or a second subscription.

The separate task-notice worker is an explicit server opt-in and polls every 30 seconds. It applies validated Accept/Decline/Update notices to existing trackers and narrowly correlated Cc watcher requests; genuine To requests remain manual accept/decline. It never accepts/declines requests or sends mail. Current AD/Exchange eligibility is checked before read/write; uncertain holds survive restarts. It is independent of Keycloak logout/revocation. See [deployment](DEPLOYMENT.md) for the shutdown/reconciliation boundary.

## Native Classic Outlook recall

`mail_recall_message` constructs and submits a native recall notice through EWS for the unchanged ordinary Sent Items source. There is no EWS recall operation. It requires `mail.send`, `mail.manage`, enabled gates, existing sender/recipient policy, current exact confirmation or the narrowly verified standing policy, and verified Send As for selected targets.

The notice preserves original To/Cc/Bcc and native source/store/search-key correlation, requests deletion of eligible unread copies and reports, and carries automatic processing/urgent priority and 48-hour expiry. Unicode subject fields remain exact. Optional legacy ANSI subject bytes are omitted when the source code page cannot encode them faithfully; no substituted characters/code page are invented.

`mail_recall_status` reads exact correlated reports from Inbox, Deleted Items and Recoverable Items Deletions. Rules moving reports elsewhere can leave the result pending/unreported. A lost/expired/damaged recall handle can be recovered read-only by passing a fresh message handle for the existing native recall notice, including in Deleted Items; this does not resubmit recall. Never reconstruct/transcribe wrapped opaque handles.

`recall_preparation_failed` with `submitted=false` and `tracking.sendStatus=not_dispatched` means preparation stopped before submission; report the bounded phase/reason and tracking ID. An uncertain submission must be reconciled through status, not repeated. Submission/report success does not establish removal of every recipient copy. Classic on-premises recall depends on eligible unread items and recipient Outlook processing. Do not force processing, change recipient settings or delete recipient mail and label that recall success.

## Verification boundary

The public release includes synthetic behavior/security checks and an optional external Exchange 2019 schema mode. See [build and test](BUILD-AND-TEST.md) for exact commands and reported skips. These checks are not a live acceptance test of another organization's Exchange, identity provider or host. Qualify a disposable pilot before broader enrollment. Native recall remains recipient-dependent, and host previews/events must be verified in the actual supported client.

## Deliberately unsupported or bounded

No Classic Outlook/OWA signature synchronization, employee endpoint helper, Outlook UI automation, arbitrary mailbox address routing, Graph/cloud Exchange dependency, active-active service deployment, unbounded assignment scheduler, opaque calendar import/export or meeting-relationship restoration is implemented. The service does not install a ChatGPT connection, force a host catalog refresh, change an existing automation prompt/memory, provide universal recall success or guarantee host widget rendering. Separate archives and Outlook-local PST/OST stores are not implied by primary-mailbox discovery.

All content remains untrusted; HTML guards and file bounds are not malware scanning. Authoritative permission/state checks, explicit approval and operational evidence remain necessary even when the client sees a tool advertised.
