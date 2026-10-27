using System.Security.Cryptography;
using System.Text;
using Microsoft.AspNetCore.DataProtection;

namespace Company.ExchangeMcp.Security;

/// <summary>Small host-local protection provider whose key survives container replacement on the audit volume.</summary>
public sealed class DurableDataProtectionProvider : IDataProtectionProvider, IDisposable
{
    private static readonly byte[] Magic = Encoding.ASCII.GetBytes("RGD1");
    private const int MaxPayloadBytes = 8 * 1024 * 1024;
    private readonly byte[] masterKey;
    public string StateDirectory { get; }

    public DurableDataProtectionProvider(string auditPath)
    {
        if (string.IsNullOrWhiteSpace(auditPath)) throw new ArgumentException("An audit path is required.", nameof(auditPath));
        var directory = StateDirectory = Path.GetFullPath(auditPath) + ".mcp-state";
        Directory.CreateDirectory(directory);
        if (!OperatingSystem.IsWindows())
            File.SetUnixFileMode(directory, UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.UserExecute);

        var keyPath = Path.Combine(directory, "protection.key");
        var statePath = Path.Combine(directory, "approvals.enc");
        if (File.Exists(keyPath))
        {
            if (!OperatingSystem.IsWindows())
            {
                var mode = File.GetUnixFileMode(keyPath);
                if ((mode & (UnixFileMode.GroupRead | UnixFileMode.GroupWrite | UnixFileMode.GroupExecute
                    | UnixFileMode.OtherRead | UnixFileMode.OtherWrite | UnixFileMode.OtherExecute)) != 0)
                    throw new UnauthorizedAccessException("The MCP protection key is not private.");
            }
            masterKey = ReadKey(keyPath);
            return;
        }

        if (File.Exists(statePath) || File.Exists(Path.Combine(directory, "approvals.initialized")))
            throw new CryptographicException("The MCP protection key is missing; refusing to replace it.");

        var candidate = RandomNumberGenerator.GetBytes(32);
        var temporary = keyPath + "." + Guid.NewGuid().ToString("N") + ".tmp";
        try
        {
            var options = new FileStreamOptions
            {
                Mode = FileMode.CreateNew,
                Access = FileAccess.Write,
                Share = FileShare.None,
                Options = FileOptions.WriteThrough
            };
            if (!OperatingSystem.IsWindows()) options.UnixCreateMode = UnixFileMode.UserRead | UnixFileMode.UserWrite;
            using (var stream = new FileStream(temporary, options))
            { stream.Write(candidate); stream.Flush(flushToDisk: true); }
            File.Move(temporary, keyPath);
            masterKey = candidate;
        }
        catch (IOException) when (File.Exists(keyPath))
        {
            CryptographicOperations.ZeroMemory(candidate);
            masterKey = ReadKey(keyPath);
        }
        finally { if (File.Exists(temporary)) File.Delete(temporary); }
    }

    private static byte[] ReadKey(string path)
    {
        if (new FileInfo(path).Length != 32) throw new CryptographicException("The MCP protection key is invalid.");
        if (!OperatingSystem.IsWindows()
            && (File.GetUnixFileMode(path) & (UnixFileMode.GroupRead | UnixFileMode.GroupWrite | UnixFileMode.GroupExecute
                | UnixFileMode.OtherRead | UnixFileMode.OtherWrite | UnixFileMode.OtherExecute)) != 0)
            throw new UnauthorizedAccessException("The MCP protection key is not private.");
        var key = File.ReadAllBytes(path);
        if (key.Length != 32) throw new CryptographicException("The MCP protection key is invalid.");
        return key;
    }

    public IDataProtector CreateProtector(string purpose)
    {
        if (string.IsNullOrWhiteSpace(purpose) || purpose.Length > 256 || purpose.Any(char.IsControl))
            throw new ArgumentException("A valid protection purpose is required.", nameof(purpose));
        return new Protector(this, [purpose]);
    }

    public void Dispose() => CryptographicOperations.ZeroMemory(masterKey);

    private byte[] Protect(string purpose, byte[] plaintext)
    {
        ArgumentNullException.ThrowIfNull(plaintext);
        if (plaintext.Length > MaxPayloadBytes) throw new CryptographicException("The protected payload is too large.");
        var nonce = RandomNumberGenerator.GetBytes(12);
        var envelope = new byte[32 + plaintext.Length];
        Magic.CopyTo(envelope, 0);
        nonce.CopyTo(envelope, 4);
        var key = DeriveKey(purpose);
        var aad = AssociatedData(purpose);
        try
        {
            using var aes = new AesGcm(key, 16);
            aes.Encrypt(nonce, plaintext, envelope.AsSpan(32), envelope.AsSpan(16, 16), aad);
            return envelope;
        }
        catch
        {
            CryptographicOperations.ZeroMemory(envelope);
            throw;
        }
        finally
        {
            CryptographicOperations.ZeroMemory(key);
            CryptographicOperations.ZeroMemory(aad);
            CryptographicOperations.ZeroMemory(nonce);
        }
    }

    private byte[] Unprotect(string purpose, byte[] protectedData)
    {
        ArgumentNullException.ThrowIfNull(protectedData);
        if (protectedData.Length is < 32 or > MaxPayloadBytes + 32
            || !protectedData.AsSpan(0, 4).SequenceEqual(Magic))
            throw new CryptographicException("The protected payload is invalid.");
        var plaintext = new byte[protectedData.Length - 32];
        var key = DeriveKey(purpose);
        var aad = AssociatedData(purpose);
        try
        {
            using var aes = new AesGcm(key, 16);
            aes.Decrypt(protectedData.AsSpan(4, 12), protectedData.AsSpan(32), protectedData.AsSpan(16, 16), plaintext, aad);
            return plaintext;
        }
        catch
        {
            CryptographicOperations.ZeroMemory(plaintext);
            throw;
        }
        finally
        {
            CryptographicOperations.ZeroMemory(key);
            CryptographicOperations.ZeroMemory(aad);
        }
    }

    private byte[] DeriveKey(string purpose)
    {
        using var hmac = new HMACSHA256(masterKey);
        return hmac.ComputeHash(Encoding.UTF8.GetBytes("Company.ExchangeMcp.DataProtection.v1\0" + purpose));
    }

    private static byte[] AssociatedData(string purpose) => Encoding.UTF8.GetBytes("RGD1\0" + purpose);

    private sealed class Protector(DurableDataProtectionProvider owner, string[] purposes) : IDataProtector
    {
        private string Purpose => string.Join("\0", purposes);
        public IDataProtector CreateProtector(string purpose)
        {
            if (string.IsNullOrWhiteSpace(purpose) || purpose.Length > 256 || purpose.Any(char.IsControl))
                throw new ArgumentException("A valid protection purpose is required.", nameof(purpose));
            return new Protector(owner, [.. purposes, purpose]);
        }
        public byte[] Protect(byte[] plaintext) => owner.Protect(Purpose, plaintext);
        public byte[] Unprotect(byte[] protectedData) => owner.Unprotect(Purpose, protectedData);
    }
}
