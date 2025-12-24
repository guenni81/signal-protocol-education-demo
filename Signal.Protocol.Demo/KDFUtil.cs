using NSec.Cryptography;

namespace Signal.Protocol.Demo;

/// <summary>
/// Provides the Key-Derivation Functions (KDF) and DH operations.
/// </summary>
public static class KDFUtil
{
    private static readonly MacAlgorithm _hmac = MacAlgorithm.HmacSha256;
    private static readonly KeyDerivationAlgorithm _hkdf = KeyDerivationAlgorithm.HkdfSha256;
    private static readonly KeyAgreementAlgorithm _agreement = KeyAgreementAlgorithm.X25519;

    /// <summary>
    /// Performs a Diffie-Hellman key agreement between a private and a public key.
    /// </summary>
    public static byte[] PerformDH(Key privateKey, PublicKey publicKey)
    {
        using var shared = _agreement.Agree(privateKey, publicKey, new SharedSecretCreationParameters { ExportPolicy = KeyExportPolicies.AllowPlaintextExport });
        return shared!.Export(SharedSecretBlobFormat.RawSharedSecret);
    }
    
    /// <summary>
    /// KDF for Root Keys (RK). Derives a new Root Key and Chain Key.
    /// KDF_RK(rk, dh_out) = (next_rk, next_ck)
    /// </summary>
    public static (byte[] RootKey, byte[] ChainKey) KDF_RK(byte[] rootKey, byte[] dhOutput, string info)
    {
        var infoBytes = System.Text.Encoding.UTF8.GetBytes(info);
        byte[] derivedBytes = _hkdf.DeriveBytes(dhOutput, rootKey, infoBytes, 64);
        
        byte[] newRootKey = new byte[32];
        System.Array.Copy(derivedBytes, 0, newRootKey, 0, 32);

        byte[] newChainKey = new byte[32];
        System.Array.Copy(derivedBytes, 32, newChainKey, 0, 32);

        return (newRootKey, newChainKey);
    }

    /// <summary>
    /// KDF for Chain Keys (CK). Derives a new Message Key and a new Chain Key.
    /// KDF_CK(ck) = (message_key, next_ck)
    /// </summary>
    public static (byte[] MessageKey, byte[] NextChainKey) KDF_CK(byte[] chainKey, string messageInfo, string chainInfo)
    {
        using var key = Key.Import(_hmac, chainKey, KeyBlobFormat.RawSymmetricKey);

        var messageInfoBytes = System.Text.Encoding.UTF8.GetBytes(messageInfo);
        var chainInfoBytes = System.Text.Encoding.UTF8.GetBytes(chainInfo);
        
        byte[] messageKey = _hmac.Mac(key, messageInfoBytes);
        byte[] nextChainKey = _hmac.Mac(key, chainInfoBytes);

        return (messageKey, nextChainKey);
    }
}
