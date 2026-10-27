using System.Xml.Linq;

namespace Company.ExchangeMcp.Exchange;

public sealed partial class EwsClient
{
    private const string SignatureConfigurationName = "CompanyMail.Signatures.v1";
    internal const int MaxSignatureConfigurationBytes = 3 * 1024 * 1024;

    public async Task<byte[]?> GetSignatureConfigurationAsync(string mailbox, CancellationToken cancellationToken)
    {
        var operation = new XElement(M + "GetUserConfiguration", SignatureConfigurationNameElement(M),
            new XElement(M + "UserConfigurationProperties", "BinaryData"));
        var document = await SendAsync(ValidateMailbox(mailbox), operation, cancellationToken,
            allowMissingUserConfiguration: true).ConfigureAwait(false);
        if (document.Descendants(M + "ResponseCode").Single().Value == "ErrorItemNotFound") return null;
        var value = RequiredElement(document, M + "UserConfiguration").Element(T + "BinaryData")?.Value;
        if (string.IsNullOrEmpty(value)) throw new InvalidOperationException("The signature configuration is invalid.");
        if (value.Length > ((MaxSignatureConfigurationBytes + 2) / 3) * 4)
            throw new InvalidOperationException("The signature configuration exceeded its size limit.");
        try
        {
            var bytes = Convert.FromBase64String(value);
            if (bytes.Length > MaxSignatureConfigurationBytes)
                throw new InvalidOperationException("The signature configuration exceeded its size limit.");
            return bytes;
        }
        catch (FormatException) { throw new InvalidOperationException("The signature configuration is invalid."); }
    }

    public async Task SaveSignatureConfigurationAsync(string mailbox, byte[] value, bool create,
        CancellationToken cancellationToken)
    {
        if (value.Length is < 1 or > MaxSignatureConfigurationBytes)
            throw new ArgumentException("The signature configuration exceeded its size limit.", nameof(value));
        var operation = new XElement(M + (create ? "CreateUserConfiguration" : "UpdateUserConfiguration"),
            new XElement(M + "UserConfiguration", SignatureConfigurationNameElement(T),
                new XElement(T + "BinaryData", Convert.ToBase64String(value))));
        await SendAsync(ValidateMailbox(mailbox), operation, cancellationToken).ConfigureAwait(false);
    }

    private static XElement SignatureConfigurationNameElement(XNamespace ns) =>
        new(ns + "UserConfigurationName", new XAttribute("Name", SignatureConfigurationName),
            new XElement(T + "DistinguishedFolderId", new XAttribute("Id", "inbox")));
}
