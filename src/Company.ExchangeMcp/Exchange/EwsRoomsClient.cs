using System.Text;
using System.Xml;
using System.Xml.Linq;

namespace Company.ExchangeMcp.Exchange;

public sealed partial class EwsClient
{
    private const int MaxRoomAddresses = 500;

    /// <summary>
    /// Returns the room lists published by Exchange. Room lists are directory data,
    /// not mailbox folders, so the operation uses the signed-in mailbox only for
    /// the authenticated EWS impersonation context.
    /// </summary>
    public async Task<IReadOnlyList<EwsRoomAddress>> ListRoomListsAsync(
        string mailbox, CancellationToken cancellationToken)
    {
        var document = await SendAsync(
            ValidateMailbox(mailbox), new XElement(M + "GetRoomLists"), cancellationToken, responseValidator: ValidateRoomResponse).ConfigureAwait(false);
        var response = RequiredRoomResponse(document, "GetRoomLists");
        return ParseRoomAddresses(response.Element(M + "RoomLists"), "room list");
    }

    /// <summary>Returns the rooms belonging to one Exchange room list.</summary>
    public async Task<IReadOnlyList<EwsRoomAddress>> ListRoomsAsync(
        string mailbox, string roomListAddress, CancellationToken cancellationToken)
    {
        var normalizedRoomList = NormalizeRoomAddress(roomListAddress, "room list");
        var operation = new XElement(
            M + "GetRooms",
            new XElement(M + "RoomList", new XElement(T + "EmailAddress", normalizedRoomList)));
        var document = await SendAsync(
            ValidateMailbox(mailbox), operation, cancellationToken, responseValidator: ValidateRoomResponse).ConfigureAwait(false);
        var response = RequiredRoomResponse(document, "GetRooms");
        var rooms = response.Element(M + "Rooms");
        if (rooms is null)
        {
            return Array.Empty<EwsRoomAddress>();
        }

        var roomElements = rooms.Elements(T + "Room").ToArray();
        if (roomElements.Length > MaxRoomAddresses)
        {
            throw new InvalidOperationException("Exchange returned too many rooms; the result was refused instead of truncated.");
        }

        return roomElements.Select(room => ParseRoomAddress(room.Element(T + "Id") ?? room, "room")).ToArray();
    }

    private static IReadOnlyList<EwsRoomAddress> ParseRoomAddresses(XElement? container, string kind)
    {
        if (container is null)
        {
            return Array.Empty<EwsRoomAddress>();
        }

        var addresses = container.Elements(T + "Address").ToArray();
        if (addresses.Length > MaxRoomAddresses)
        {
            throw new InvalidOperationException($"Exchange returned too many {kind}s; the result was refused instead of truncated.");
        }

        return addresses.Select(address => ParseRoomAddress(address, kind)).ToArray();
    }

    private static EwsRoomAddress ParseRoomAddress(XElement address, string kind)
    {
        var value = NormalizeRoomAddress(address.Element(T + "EmailAddress")?.Value, kind);
        var name = address.Element(T + "Name")?.Value ?? value;
        if (name.Length > 255 || name.Any(char.IsControl))
        {
            throw new InvalidOperationException($"Exchange returned an invalid {kind} name.");
        }

        return new EwsRoomAddress(
            name,
            value,
            address.Element(T + "RoutingType")?.Value ?? "SMTP",
            address.Element(T + "MailboxType")?.Value ?? "Mailbox");
    }

    private static string NormalizeRoomAddress(string? address, string kind)
    {
        if (string.IsNullOrWhiteSpace(address) || !IsPlainMailbox(address))
        {
            throw new InvalidOperationException($"Exchange returned an invalid {kind} address.");
        }

        return new System.Net.Mail.MailAddress(address).Address;
    }

    private static XElement RequiredRoomResponse(XDocument document, string operation)
    {
        var response = document.Root?.Element(Soap + "Body")?.Element(M + (operation + "Response"));
        if (document.Root?.Name != Soap + "Envelope" || document.Root.Element(Soap + "Body")?.Elements().Count() != 1
            || response is null)
        {
            throw new InvalidOperationException("Exchange returned an incomplete room response.");
        }

        return response;
    }

    private static void ValidateRoomResponse(XDocument document, string operation)
    {
        var response = RequiredRoomResponse(document, operation);
        if (document.Descendants(Soap + "Fault").Any()
            || !string.Equals((string?)response.Attribute("ResponseClass"), "Success", StringComparison.Ordinal)
            || !string.Equals(response.Element(M + "ResponseCode")?.Value, "NoError", StringComparison.Ordinal))
            throw new InvalidOperationException("Exchange returned an unsuccessful room response.");
    }
}
