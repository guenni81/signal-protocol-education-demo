using NSec.Cryptography;
using System.Collections.Generic;
using System.Linq;

namespace Signal.Protocol.Demo;

/// <summary>
/// Performs the X3DH handshake between two DEVICES to establish a shared secret.
/// </summary>
public static class X3DHSession
{
    /// <summary>
    /// The initial message from the initiator device to the responder device.
    /// </summary>
    public class InitialMessage
    {
        public PublicKey InitiatorIdentityKey { get; }
        public PublicKey InitiatorEphemeralKey { get; }
        public string? RecipientOneTimePreKeyId { get; }

        public InitialMessage(PublicKey initiatorIdentityKey, PublicKey initiatorEphemeralKey, string? recipientOneTimePreKeyId)
        {
            InitiatorIdentityKey = initiatorIdentityKey;
            InitiatorEphemeralKey = initiatorEphemeralKey;
            RecipientOneTimePreKeyId = recipientOneTimePreKeyId;
        }
    }

    /// <summary>
    /// Initiates a session from the initiator device's side.
    /// </summary>
    /// <returns>The shared secret, the initial message, the responder's initial ratchet key, and the initiator's ephemeral private key.</returns>
    public static (byte[] SharedSecret, InitialMessage InitialMsg, PublicKey InitialRatchetKey, Key InitiatorEphemeralKey) InitiateSession(Device initiatorDevice, PreKeyBundle recipientBundle)
    {
        if(DebugMode.Enabled) TraceLogger.Log(TraceCategory.X3DH, $"--- X3DH INITIATION: {initiatorDevice.Id} -> {recipientBundle.DeviceId} ---");
        var creationParams = new SharedSecretCreationParameters { ExportPolicy = KeyExportPolicies.AllowPlaintextExport };
        
        // Verify the signature of the recipient's signed pre-key
        var isSignatureValid = SignatureAlgorithm.Ed25519.Verify(recipientBundle.PublicIdentitySigningKey, recipientBundle.PublicSignedPreKey.Export(KeyBlobFormat.RawPublicKey), recipientBundle.SignedPreKeySignature);
        if(DebugMode.Enabled) TraceLogger.Log(TraceCategory.X3DH, $"Verifying signature of SignedPreKey from {recipientBundle.DeviceId}: {(isSignatureValid ? "SUCCESS" : "FAILED")}");
        if (!isSignatureValid) throw new System.Security.SecurityException("Invalid signature on PreKeyBundle.");

        var ephemeralKey = Key.Create(KeyAgreementAlgorithm.X25519, new KeyCreationParameters { ExportPolicy = KeyExportPolicies.AllowPlaintextExport });
        if(DebugMode.Enabled) TraceLogger.LogKey(TraceCategory.X3DH, "Initiator EphemeralKey (Private)", ephemeralKey.Export(KeyBlobFormat.RawPrivateKey));

        // Perform the 4 DH calculations
        if(DebugMode.Enabled) TraceLogger.Log(TraceCategory.X3DH, "Calculating 3-4 Diffie-Hellman agreements...");
        using var dh1 = KeyAgreementAlgorithm.X25519.Agree(initiatorDevice.KeyManager.IdentityAgreementKey, recipientBundle.PublicSignedPreKey, creationParams);
        if(DebugMode.Enabled) TraceLogger.LogKey(TraceCategory.X3DH, "  DH1 (IK_A, SPK_B)", dh1!.Export(SharedSecretBlobFormat.RawSharedSecret));
        
        using var dh2 = KeyAgreementAlgorithm.X25519.Agree(ephemeralKey, recipientBundle.PublicIdentityAgreementKey, creationParams);
        if(DebugMode.Enabled) TraceLogger.LogKey(TraceCategory.X3DH, "  DH2 (EK_A, IK_B)", dh2!.Export(SharedSecretBlobFormat.RawSharedSecret));

        using var dh3 = KeyAgreementAlgorithm.X25519.Agree(ephemeralKey, recipientBundle.PublicSignedPreKey, creationParams);
        if(DebugMode.Enabled) TraceLogger.LogKey(TraceCategory.X3DH, "  DH3 (EK_A, SPK_B)", dh3!.Export(SharedSecretBlobFormat.RawSharedSecret));
        
        byte[]? dh4Bytes = null;
        if (recipientBundle.PublicOneTimePreKey != null)
        {
            using var dh4 = KeyAgreementAlgorithm.X25519.Agree(ephemeralKey, recipientBundle.PublicOneTimePreKey, creationParams);
            dh4Bytes = dh4!.Export(SharedSecretBlobFormat.RawSharedSecret);
            if(DebugMode.Enabled) TraceLogger.LogKey(TraceCategory.X3DH, "  DH4 (EK_A, OPK_B)", dh4Bytes);
        }

        // Concatenate the DH results and derive the final secret
        var ikm = Concat(dh1!.Export(SharedSecretBlobFormat.RawSharedSecret), dh2!.Export(SharedSecretBlobFormat.RawSharedSecret), dh3!.Export(SharedSecretBlobFormat.RawSharedSecret), dh4Bytes);
        if(DebugMode.Enabled) TraceLogger.LogKey(TraceCategory.X3DH, "IKM (Intermediate Key Material)", ikm);
        
        var sharedSecret = DeriveSharedSecret(ikm);
        if(DebugMode.Enabled) TraceLogger.LogKey(TraceCategory.X3DH, "SK (Shared Secret)", sharedSecret);
        if(DebugMode.Enabled) TraceLogger.Log(TraceCategory.X3DH, "--- X3DH INITIATION COMPLETE ---\n");

        var initialMessage = new InitialMessage(initiatorDevice.KeyManager.IdentityAgreementKey.PublicKey, ephemeralKey.PublicKey, recipientBundle.PublicOneTimePreKeyId);
        
        return (sharedSecret, initialMessage, recipientBundle.PublicSignedPreKey, ephemeralKey);
    }
    
    /// <summary>
    /// Establishes a session from the responder device's side.
    /// </summary>
    /// <returns>The shared secret and the initiator's initial ratchet key.</returns>
    public static (byte[] SharedSecret, PublicKey InitialRatchetKey) EstablishSession(Device recipientDevice, InitialMessage message)
    {
        if(DebugMode.Enabled) TraceLogger.Log(TraceCategory.X3DH, $"--- X3DH ESTABLISHMENT: {recipientDevice.Id} receives from initiator ---");
        var creationParams = new SharedSecretCreationParameters { ExportPolicy = KeyExportPolicies.AllowPlaintextExport };
        
        Key? oneTimePreKey = null;
        if (!string.IsNullOrEmpty(message.RecipientOneTimePreKeyId))
        {
            oneTimePreKey = recipientDevice.KeyManager.GetOneTimePreKey(message.RecipientOneTimePreKeyId);
        } else {
            if(DebugMode.Enabled) TraceLogger.Log(TraceCategory.X3DH, "Proceeding with X3DH without a one-time pre-key.");
        }

        // Perform the 4 DH calculations from the responder's perspective
        if(DebugMode.Enabled) TraceLogger.Log(TraceCategory.X3DH, "Calculating 3-4 Diffie-Hellman agreements...");
        using var dh1 = KeyAgreementAlgorithm.X25519.Agree(recipientDevice.KeyManager.SignedPreKey, message.InitiatorIdentityKey, creationParams);
        if(DebugMode.Enabled) TraceLogger.LogKey(TraceCategory.X3DH, "  DH1 (SPK_B, IK_A)", dh1!.Export(SharedSecretBlobFormat.RawSharedSecret));
        
        using var dh2 = KeyAgreementAlgorithm.X25519.Agree(recipientDevice.KeyManager.IdentityAgreementKey, message.InitiatorEphemeralKey, creationParams);
        if(DebugMode.Enabled) TraceLogger.LogKey(TraceCategory.X3DH, "  DH2 (IK_B, EK_A)", dh2!.Export(SharedSecretBlobFormat.RawSharedSecret));

        using var dh3 = KeyAgreementAlgorithm.X25519.Agree(recipientDevice.KeyManager.SignedPreKey, message.InitiatorEphemeralKey, creationParams);
        if(DebugMode.Enabled) TraceLogger.LogKey(TraceCategory.X3DH, "  DH3 (SPK_B, EK_A)", dh3!.Export(SharedSecretBlobFormat.RawSharedSecret));
        
        byte[]? dh4Bytes = null;
        if (oneTimePreKey != null)
        {
            using var dh4 = KeyAgreementAlgorithm.X25519.Agree(oneTimePreKey, message.InitiatorEphemeralKey, creationParams);
            dh4Bytes = dh4!.Export(SharedSecretBlobFormat.RawSharedSecret);
            if(DebugMode.Enabled) TraceLogger.LogKey(TraceCategory.X3DH, "  DH4 (OPK_B, EK_A)", dh4Bytes);
            oneTimePreKey.Dispose();
        }

        // Concatenate and derive the final secret
        var ikm = Concat(dh1!.Export(SharedSecretBlobFormat.RawSharedSecret), dh2!.Export(SharedSecretBlobFormat.RawSharedSecret), dh3!.Export(SharedSecretBlobFormat.RawSharedSecret), dh4Bytes);
        if(DebugMode.Enabled) TraceLogger.LogKey(TraceCategory.X3DH, "IKM (Intermediate Key Material)", ikm);
        
        var sharedSecret = DeriveSharedSecret(ikm);
        if(DebugMode.Enabled) TraceLogger.LogKey(TraceCategory.X3DH, "SK (Shared Secret)", sharedSecret);
        if(DebugMode.Enabled) TraceLogger.Log(TraceCategory.X3DH, "--- X3DH ESTABLISHMENT COMPLETE ---\n");

        return (sharedSecret, message.InitiatorEphemeralKey);
    }

    public static byte[] DeriveSharedSecret(byte[] ikm)
    {
        var salt = new byte[32]; // A salt of zero-bytes
        var info = System.Text.Encoding.UTF8.GetBytes("X3DH");
        return KeyDerivationAlgorithm.HkdfSha256.DeriveBytes(ikm, salt, info, 32);
    }

    public static byte[] Concat(params byte[]?[] arrays)
    {
        var result = new List<byte>();
        foreach (var arr in arrays)
        {
            if (arr != null) result.AddRange(arr);
        }
        return result.ToArray();
    }
}
