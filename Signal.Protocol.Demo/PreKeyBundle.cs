using NSec.Cryptography;

namespace Signal.Protocol.Demo;

/// <summary>
/// Represents a Pre-Key bundle for a specific device,
/// required for an X3DH handshake.
/// </summary>
public class PreKeyBundle
{
    /// <summary>
    /// The ID of the device to which this bundle belongs.
    /// </summary>
    public string DeviceId { get; }
    
    /// <summary>
    /// The public identity signing key.
    /// </summary>
    public PublicKey PublicIdentitySigningKey { get; }
    
    /// <summary>
    /// The public identity agreement key.
    /// </summary>
    public PublicKey PublicIdentityAgreementKey { get; }
    
    /// <summary>
    /// The public signed pre-key.
    /// </summary>
    public PublicKey PublicSignedPreKey { get; }
    
    /// <summary>
    /// The signature of the signed pre-key.
    /// </summary>
    public byte[] SignedPreKeySignature { get; }
    
    /// <summary>
    /// An optional public one-time pre-key.
    /// </summary>
    public PublicKey? PublicOneTimePreKey { get; }
    
    /// <summary>
    /// The ID of the optional one-time pre-key.
    /// </summary>
    public string? PublicOneTimePreKeyId { get; }

    public PreKeyBundle(
        string deviceId,
        PublicKey publicIdentitySigningKey,
        PublicKey publicIdentityAgreementKey,
        PublicKey publicSignedPreKey,
        byte[] signedPreKeySignature,
        (string KeyId, PublicKey Key)? oneTimePreKey)
    {
        DeviceId = deviceId;
        PublicIdentitySigningKey = publicIdentitySigningKey;
        PublicIdentityAgreementKey = publicIdentityAgreementKey;
        PublicSignedPreKey = publicSignedPreKey;
        SignedPreKeySignature = signedPreKeySignature;
        PublicOneTimePreKey = oneTimePreKey?.Key;
        PublicOneTimePreKeyId = oneTimePreKey?.KeyId;
    }
}
