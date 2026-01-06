using System;

namespace Signal.Protocol.Demo;

/// <summary>
/// Carries the classical X3DH initial message plus the ML-KEM ciphertext.
/// </summary>
public sealed class PQXdhMessageBundle
{
    public X3DHSession.InitialMessage ClassicalMessage { get; }
    public byte[] PostQuantumCiphertext { get; }
    public string RecipientPostQuantumPreKeyId { get; }
    public bool RecipientPostQuantumPreKeyIsOneTime { get; }

    public PQXdhMessageBundle(
        X3DHSession.InitialMessage classicalMessage,
        byte[] postQuantumCiphertext,
        string recipientPostQuantumPreKeyId,
        bool recipientPostQuantumPreKeyIsOneTime)
    {
        ClassicalMessage = classicalMessage;
        PostQuantumCiphertext = postQuantumCiphertext;
        RecipientPostQuantumPreKeyId = recipientPostQuantumPreKeyId;
        RecipientPostQuantumPreKeyIsOneTime = recipientPostQuantumPreKeyIsOneTime;
    }
}
