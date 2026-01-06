using NSec.Cryptography;
using System;

namespace Signal.Protocol.Demo;

/// <summary>
/// Performs a hybrid PQXDH handshake: classical X3DH + ML-KEM (Kyber).
/// </summary>
public static class PQXdhSession
{
    /// <summary>
    /// Initiates a PQXDH session from the initiator device's side.
    /// </summary>
    public static (byte[] RootKey, PQXdhMessageBundle InitialBundle, PublicKey InitialRatchetKey) InitiateSession(Device initiatorDevice, PreKeyBundle recipientBundle)
    {
        if (DebugMode.Enabled)
        {
            TraceLogger.Log(TraceCategory.X3DH, $"--- PQXDH INITIATION: {initiatorDevice.Id} -> {recipientBundle.DeviceId} ---");
        }

        var (classicalSecret, classicalMessage, responderInitialRatchetKey) = X3DHSession.InitiateSession(initiatorDevice, recipientBundle);

        var pqRecipientKey = recipientBundle.PublicPostQuantumOneTimePreKey ?? recipientBundle.PublicPostQuantumPreKey;
        var pqRecipientKeyId = pqRecipientKey?.KeyId;
        var pqRecipientKeyIsOneTime = recipientBundle.PublicPostQuantumOneTimePreKey.HasValue;

        if (pqRecipientKey == null || string.IsNullOrEmpty(pqRecipientKeyId))
        {
            throw new InvalidOperationException($"No PQ prekey available for {recipientBundle.DeviceId}.");
        }

        if (DebugMode.Enabled)
        {
            TraceLogger.Log(TraceCategory.X3DH, $"Using PQ prekey {pqRecipientKeyId.Substring(0, 10)}... ({(pqRecipientKeyIsOneTime ? "One-Time" : "Identity")}).");
        }

        var (ciphertext, pqSharedSecret) = initiatorDevice.PostQuantumKeyManager.Encapsulate(pqRecipientKey.Value);
        if (DebugMode.Enabled)
        {
            TraceLogger.LogKey(TraceCategory.X3DH, "PQ Encapsulation (Ciphertext)", ciphertext);
            TraceLogger.LogKey(TraceCategory.X3DH, "PQ Shared Secret", pqSharedSecret);
        }

        var hybridIkm = X3DHSession.Concat(classicalSecret, pqSharedSecret);
        var rootKey = X3DHSession.DeriveSharedSecret(hybridIkm);

        if (DebugMode.Enabled)
        {
            TraceLogger.LogKey(TraceCategory.X3DH, "Hybrid IKM (Classical || PQ)", hybridIkm);
            TraceLogger.LogKey(TraceCategory.X3DH, "PQXDH Root Key", rootKey);
            TraceLogger.Log(TraceCategory.X3DH, "--- PQXDH INITIATION COMPLETE ---\n");
        }

        var bundle = new PQXdhMessageBundle(classicalMessage, ciphertext, pqRecipientKeyId, pqRecipientKeyIsOneTime);
        return (rootKey, bundle, responderInitialRatchetKey);
    }

    /// <summary>
    /// Establishes a PQXDH session from the responder device's side.
    /// </summary>
    public static (byte[] RootKey, PublicKey InitialRatchetKey) EstablishSession(Device recipientDevice, PQXdhMessageBundle bundle)
    {
        if (DebugMode.Enabled)
        {
            TraceLogger.Log(TraceCategory.X3DH, $"--- PQXDH ESTABLISHMENT: {recipientDevice.Id} receives from initiator ---");
        }

        var (classicalSecret, initiatorInitialRatchetKey) = X3DHSession.EstablishSession(recipientDevice, bundle.ClassicalMessage);

        PostQuantumPreKey? pqRecipientKey = null;
        if (bundle.RecipientPostQuantumPreKeyIsOneTime)
        {
            pqRecipientKey = recipientDevice.PostQuantumKeyManager.GetOneTimePreKey(bundle.RecipientPostQuantumPreKeyId);
            if (pqRecipientKey == null)
            {
                throw new InvalidOperationException($"PQ one-time prekey {bundle.RecipientPostQuantumPreKeyId} not found for {recipientDevice.Id}.");
            }
        }
        else
        {
            pqRecipientKey = recipientDevice.PostQuantumKeyManager.PostQuantumPreKey;
        }

        var pqSharedSecret = recipientDevice.PostQuantumKeyManager.Decapsulate(pqRecipientKey, bundle.PostQuantumCiphertext);
        if (DebugMode.Enabled)
        {
            TraceLogger.LogKey(TraceCategory.X3DH, "PQ Shared Secret", pqSharedSecret);
        }

        var hybridIkm = X3DHSession.Concat(classicalSecret, pqSharedSecret);
        var rootKey = X3DHSession.DeriveSharedSecret(hybridIkm);

        if (DebugMode.Enabled)
        {
            TraceLogger.LogKey(TraceCategory.X3DH, "Hybrid IKM (Classical || PQ)", hybridIkm);
            TraceLogger.LogKey(TraceCategory.X3DH, "PQXDH Root Key", rootKey);
            TraceLogger.Log(TraceCategory.X3DH, "--- PQXDH ESTABLISHMENT COMPLETE ---\n");
        }

        return (rootKey, initiatorInitialRatchetKey);
    }
}
