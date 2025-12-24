using System;
using System.Collections.Concurrent;
using NSec.Cryptography;

namespace Signal.Protocol.Demo;

/// <summary>
/// Manages the cryptographic keys for a device according to the X3DH model.
/// In this demo implementation, the generation of each key is logged in detail.
/// </summary>
public class KeyManager
{
    public Key IdentitySigningKey { get; }
    public Key IdentityAgreementKey { get; }
    public Key SignedPreKey { get; }
    public byte[] SignedPreKeySignature { get; }
    private readonly ConcurrentDictionary<string, Key> _oneTimePreKeys;

    public KeyManager()
    {
        // An export policy that allows reading the private keys for DH agreement and logging.
        // IN PRODUCTION SYSTEMS, THIS SHOULD NEVER BE 'AllowPlaintextExport'!
        var keyCreationParameters = new KeyCreationParameters { ExportPolicy = KeyExportPolicies.AllowPlaintextExport };
        
        if(DebugMode.Enabled) TraceLogger.Log(TraceCategory.KEYGEN, "--- Generating new keys for a device ---");

        // Long-term Identity Key
        IdentitySigningKey = Key.Create(SignatureAlgorithm.Ed25519, keyCreationParameters);
        if(DebugMode.Enabled) TraceLogger.LogKey(TraceCategory.KEYGEN, "IdentitySigningKey (Private)", IdentitySigningKey.Export(KeyBlobFormat.RawPrivateKey));
        if(DebugMode.Enabled) TraceLogger.LogKey(TraceCategory.KEYGEN, "IdentitySigningKey (Public)", IdentitySigningKey.PublicKey.Export(KeyBlobFormat.RawPublicKey));

        IdentityAgreementKey = Key.Create(KeyAgreementAlgorithm.X25519, keyCreationParameters);
        if(DebugMode.Enabled) TraceLogger.LogKey(TraceCategory.KEYGEN, "IdentityAgreementKey (Private)", IdentityAgreementKey.Export(KeyBlobFormat.RawPrivateKey));
        if(DebugMode.Enabled) TraceLogger.LogKey(TraceCategory.KEYGEN, "IdentityAgreementKey (Public)", IdentityAgreementKey.PublicKey.Export(KeyBlobFormat.RawPublicKey));
        
        // Signed PreKey
        SignedPreKey = Key.Create(KeyAgreementAlgorithm.X25519, keyCreationParameters);
        if(DebugMode.Enabled) TraceLogger.LogKey(TraceCategory.KEYGEN, "SignedPreKey (Private)", SignedPreKey.Export(KeyBlobFormat.RawPrivateKey));
        if(DebugMode.Enabled) TraceLogger.LogKey(TraceCategory.KEYGEN, "SignedPreKey (Public)", SignedPreKey.PublicKey.Export(KeyBlobFormat.RawPublicKey));
        
        // Signature of the SignedPreKey
        SignedPreKeySignature = SignatureAlgorithm.Ed25519.Sign(
            IdentitySigningKey,
            SignedPreKey.PublicKey.Export(KeyBlobFormat.RawPublicKey)
        );
        if(DebugMode.Enabled) TraceLogger.Log(TraceCategory.KEYGEN, $"SignedPreKey-Signature: {Convert.ToBase64String(SignedPreKeySignature)}");

        // One-Time PreKeys
        _oneTimePreKeys = new ConcurrentDictionary<string, Key>();
        if(DebugMode.Enabled) TraceLogger.Log(TraceCategory.KEYGEN, "Generating 10 One-Time PreKeys...");
        for (int i = 0; i < 10; i++)
        {
            var oneTimeKey = Key.Create(KeyAgreementAlgorithm.X25519, keyCreationParameters);
            var keyId = Convert.ToBase64String(oneTimeKey.PublicKey.Export(KeyBlobFormat.RawPublicKey));
            _oneTimePreKeys[keyId] = oneTimeKey;
            
            if(DebugMode.Enabled) TraceLogger.Log(TraceCategory.KEYGEN, $"--- OTP #{i + 1} ---");
            if(DebugMode.Enabled) TraceLogger.LogKey(TraceCategory.KEYGEN, "  OneTimePreKey (Private)", oneTimeKey.Export(KeyBlobFormat.RawPrivateKey));
            if(DebugMode.Enabled) TraceLogger.LogKey(TraceCategory.KEYGEN, "  OneTimePreKey (Public, ID)", oneTimeKey.PublicKey.Export(KeyBlobFormat.RawPublicKey));
        }
        if(DebugMode.Enabled) TraceLogger.Log(TraceCategory.KEYGEN, "--- Key generation for device complete ---");
    }
    
    public Dictionary<string, PublicKey> GetPublicOneTimePreKeys()
    {
        return _oneTimePreKeys.ToDictionary(pair => pair.Key, pair => pair.Value.PublicKey);
    }
    
    /// <summary>
    /// Retrieves a One-Time PreKey by its ID and removes it from storage.
    /// This ensures that it is only used once.
    /// </summary>
    public Key? GetOneTimePreKey(string keyId)
    {
        if (_oneTimePreKeys.TryRemove(keyId, out var key))
        {
            if(DebugMode.Enabled) TraceLogger.Log(TraceCategory.KEYGEN, $"One-Time PreKey {keyId.Substring(0, 10)}... was fetched from the server and removed.");
            return key;
        }
        if(DebugMode.Enabled) TraceLogger.Log(TraceCategory.KEYGEN, $"WARNING: One-Time PreKey {keyId.Substring(0, 10)}... was requested but was no longer available.");
        return null;
    }
}