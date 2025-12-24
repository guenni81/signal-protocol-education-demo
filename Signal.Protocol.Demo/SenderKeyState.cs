using NSec.Cryptography;
using System.Collections.Generic;
using System.Linq;

namespace Signal.Protocol.Demo;

/// <summary>
/// Defines the state of a sender for a specific group (Sender Keys).
/// </summary>
public class SenderKeyState
{
    private const int MAX_SKIPPED_KEYS = 50;
    
    private readonly string _loggingId;

    public Key? SigningKey { get; }
    public PublicKey SigningPublicKey { get; }
    public byte[] ChainKey { get; private set; }
    public uint MessageCounter { get; private set; }
    public Dictionary<uint, byte[]> SkippedMessageKeys { get; }

    private SenderKeyState(Key signingKey, byte[] chainKey, string loggingId)
    {
        _loggingId = loggingId;
        SigningKey = signingKey;
        SigningPublicKey = signingKey.PublicKey;
        ChainKey = chainKey;
        MessageCounter = 0;
        SkippedMessageKeys = new Dictionary<uint, byte[]>();
        
        TraceLogger.Log(TraceCategory.GROUP, $"--- [{_loggingId}] New SenderKeyState created (SENDER) ---");
        TraceLogger.LogKey(TraceCategory.GROUP, "  SigningKey (Private)", SigningKey.Export(KeyBlobFormat.RawPrivateKey));
        TraceLogger.LogKey(TraceCategory.GROUP, "  Initial ChainKey", ChainKey);
    }
    
    private SenderKeyState(PublicKey signingPublicKey, byte[] chainKey, string loggingId)
    {
        _loggingId = loggingId;
        SigningKey = null;
        SigningPublicKey = signingPublicKey;
        ChainKey = chainKey;
        MessageCounter = 0;
        SkippedMessageKeys = new Dictionary<uint, byte[]>();
        
        TraceLogger.Log(TraceCategory.GROUP, $"--- [{_loggingId}] New SenderKeyState created (RECEIVER) ---");
        TraceLogger.LogKey(TraceCategory.GROUP, "  SigningKey (Public)", SigningPublicKey.Export(KeyBlobFormat.RawPublicKey));
        TraceLogger.LogKey(TraceCategory.GROUP, "  Initial ChainKey", ChainKey);
    }

    public static SenderKeyState Create(string loggingId)
    {
        var signingKey = Key.Create(SignatureAlgorithm.Ed25519, new KeyCreationParameters { ExportPolicy = KeyExportPolicies.AllowPlaintextExport });
        var chainKey = new byte[32];
        System.Security.Cryptography.RandomNumberGenerator.Fill(chainKey);
        return new SenderKeyState(signingKey, chainKey, loggingId);
    }

    public static SenderKeyState CreateFromDistributedKeys(PublicKey signingPublicKey, byte[] chainKey, string loggingId)
    {
        return new SenderKeyState(signingPublicKey, chainKey, loggingId);
    }
    
    public byte[] SenderRatchetStep()
    {
        TraceLogger.Log(TraceCategory.GROUP, $"[{_loggingId}] SenderRatchetStep: Generating key for message C={MessageCounter}");
        TraceLogger.LogKey(TraceCategory.GROUP, "  Current ChainKey", ChainKey);

        var (messageKey, nextChainKey) = GetNextKeys();
        ChainKey = nextChainKey;
        
        TraceLogger.LogKey(TraceCategory.GROUP, "  -> Derived MessageKey", messageKey);
        TraceLogger.LogKey(TraceCategory.GROUP, "  -> Next ChainKey", ChainKey);
        
        MessageCounter++;
        return messageKey;
    }

    public byte[]? GetReceiverMessageKey(uint messageCounter)
    {
        TraceLogger.Log(TraceCategory.GROUP, $"[{_loggingId}] GetReceiverMessageKey: Key for C={messageCounter} requested.");
        
        if (messageCounter < MessageCounter)
        {
            if (SkippedMessageKeys.TryGetValue(messageCounter, out var skippedKey))
            {
                TraceLogger.Log(TraceCategory.ORDERING, $"[{_loggingId}] Decrypting delayed message C={messageCounter} with stored key.");
                TraceLogger.LogKey(TraceCategory.ORDERING, "  Used SkippedKey", skippedKey);
                SkippedMessageKeys.Remove(messageCounter);
                return skippedKey;
            }
            TraceLogger.Log(TraceCategory.ORDERING, $"[!!!] WARNING: Message C={messageCounter} is too old and no matching key is in the cache. REPLAY? Discarding...");
            return null; // Message is too old or a replay attack
        }

        if (messageCounter > MessageCounter)
        {
            TraceLogger.Log(TraceCategory.ORDERING, $"[{_loggingId}] Expected C={MessageCounter}, but got C={messageCounter}. Advancing chain...");
        }
        
        while (MessageCounter < messageCounter)
        {
            if (SkippedMessageKeys.Count >= MAX_SKIPPED_KEYS)
            {
                TraceLogger.Log(TraceCategory.ORDERING, $"[!!!] Maximum number of skipped keys ({MAX_SKIPPED_KEYS}) reached. Discarding oldest.");
                SkippedMessageKeys.Remove(SkippedMessageKeys.Keys.First());
            }
            
            var (skippedMessageKey, nextChainKey) = GetNextKeys();
            SkippedMessageKeys[MessageCounter] = skippedMessageKey;
            TraceLogger.LogKey(TraceCategory.ORDERING, $"  -> Storing SkippedKey for C={MessageCounter}", skippedMessageKey);
            ChainKey = nextChainKey;
            MessageCounter++;
        }
        
        if (MessageCounter == messageCounter)
        {
            TraceLogger.Log(TraceCategory.GROUP, $"[{_loggingId}] Reached C={messageCounter}. Deriving key.");
            var (messageKey, nextChainKey) = GetNextKeys();
            ChainKey = nextChainKey;
            MessageCounter++;
            return messageKey;
        }

        return null;
    }
    
    private (byte[] MessageKey, byte[] NextChainKey) GetNextKeys()
    {
        // The KDF for sender keys uses HMAC-SHA256 with the current ChainKey as the key.
        // An input of 0x01 produces the message key.
        // An input of 0x02 produces the next chain key.
        return KDFUtil.KDF_CK(ChainKey, "\x01", "\x02");
    }
}
