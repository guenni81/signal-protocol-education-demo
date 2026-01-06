using System;
using System.Collections.Concurrent;
using Org.BouncyCastle.Crypto.Kems;
using Org.BouncyCastle.Crypto.Parameters;

namespace Signal.Protocol.Demo;

/// <summary>
/// Manages ML-KEM Post-Quantum identity and one-time prekeys for a device.
/// Demo-only: this keeps private key bytes in memory for tracing and testing.
/// </summary>
public sealed class PostQuantumKeyManager
{
    public PostQuantumPreKey PostQuantumPreKey { get; }
    public MLKemParameters Parameters { get; }
    private readonly ConcurrentDictionary<string, PostQuantumPreKey> _oneTimePreKeys;

    public PostQuantumKeyManager(MLKemParameters? parameters = null, int oneTimePreKeyCount = 10)
    {
        Parameters = parameters ?? MLKemParameters.ml_kem_512;

        if (DebugMode.Enabled)
        {
            TraceLogger.Log(TraceCategory.KEYGEN, $"--- Generating PQ keys (ML-KEM: {Parameters.Name}) ---");
        }

        PostQuantumPreKey = PostQuantumPreKey.Generate(Parameters);
        if (DebugMode.Enabled)
        {
            TraceLogger.LogKey(TraceCategory.KEYGEN, "PQ Pre Key (Private)", PostQuantumPreKey.PrivateKey);
            TraceLogger.LogKey(TraceCategory.KEYGEN, "PQ Pre Key (Public)", PostQuantumPreKey.PublicKey);
        }

        _oneTimePreKeys = new ConcurrentDictionary<string, PostQuantumPreKey>();
        if (DebugMode.Enabled)
        {
            TraceLogger.Log(TraceCategory.KEYGEN, $"Generating {oneTimePreKeyCount} PQ One-Time PreKeys...");
        }

        for (int i = 0; i < oneTimePreKeyCount; i++)
        {
            var oneTimeKey = PostQuantumPreKey.Generate(Parameters);
            _oneTimePreKeys[oneTimeKey.KeyId] = oneTimeKey;

            if (DebugMode.Enabled)
            {
                TraceLogger.Log(TraceCategory.KEYGEN, $"--- PQ OTP #{i + 1} ---");
                TraceLogger.LogKey(TraceCategory.KEYGEN, "  PQ OneTimePreKey (Private)", oneTimeKey.PrivateKey);
                TraceLogger.LogKey(TraceCategory.KEYGEN, "  PQ OneTimePreKey (Public, ID)", oneTimeKey.PublicKey);
            }
        }

        if (DebugMode.Enabled)
        {
            TraceLogger.Log(TraceCategory.KEYGEN, "--- PQ key generation for device complete ---");
        }
    }

    public PostQuantumPublicPreKey PublicIdentityKey => PostQuantumPreKey.ToPublic();

    public Dictionary<string, PostQuantumPublicPreKey> GetPublicOneTimePreKeys()
    {
        return _oneTimePreKeys.ToDictionary(pair => pair.Key, pair => pair.Value.ToPublic());
    }

    /// <summary>
    /// Retrieves a PQ One-Time PreKey by its ID and removes it from storage.
    /// </summary>
    public PostQuantumPreKey? GetOneTimePreKey(string keyId)
    {
        if (_oneTimePreKeys.TryRemove(keyId, out var key))
        {
            if (DebugMode.Enabled)
            {
                TraceLogger.Log(TraceCategory.KEYGEN, $"PQ One-Time PreKey {keyId.Substring(0, 10)}... was fetched from the server and removed.");
            }
            return key;
        }

        if (DebugMode.Enabled)
        {
            TraceLogger.Log(TraceCategory.KEYGEN, $"WARNING: PQ One-Time PreKey {keyId.Substring(0, 10)}... was requested but was no longer available.");
        }

        return null;
    }

    /// <summary>
    /// Encapsulates a shared secret to a recipient's public ML-KEM key.
    /// </summary>
    public (byte[] Encapsulation, byte[] SharedSecret) Encapsulate(PostQuantumPublicPreKey recipientKey)
    {
        var parameters = ResolveParameters(recipientKey.ParameterName);
        var publicKeyParameters = MLKemPublicKeyParameters.FromEncoding(parameters, recipientKey.PublicKey);
        var encapsulator = new MLKemEncapsulator(parameters);
        encapsulator.Init(publicKeyParameters);

        var encapsulation = new byte[encapsulator.EncapsulationLength];
        var secret = new byte[encapsulator.SecretLength];
        encapsulator.Encapsulate(encapsulation, 0, encapsulation.Length, secret, 0, secret.Length);

        return (encapsulation, secret);
    }

    /// <summary>
    /// Decapsulates a shared secret using the recipient's private ML-KEM key.
    /// </summary>
    public byte[] Decapsulate(PostQuantumPreKey recipientKey, byte[] encapsulation)
    {
        var parameters = ResolveParameters(recipientKey.ParameterName);
        var privateKeyParameters = MLKemPrivateKeyParameters.FromEncoding(parameters, recipientKey.PrivateKey);
        var decapsulator = new MLKemDecapsulator(parameters);
        decapsulator.Init(privateKeyParameters);

        var secret = new byte[decapsulator.SecretLength];
        decapsulator.Decapsulate(encapsulation, 0, encapsulation.Length, secret, 0, secret.Length);

        return secret;
    }

    public static MLKemParameters ResolveParameters(string parameterName)
    {
        if (string.IsNullOrWhiteSpace(parameterName))
        {
            throw new ArgumentException("ML-KEM parameter name must be provided.", nameof(parameterName));
        }

        var normalized = parameterName.Trim().ToLowerInvariant().Replace("-", "_");
        return normalized switch
        {
            "ml_kem_512" => MLKemParameters.ml_kem_512,
            "ml_kem_768" => MLKemParameters.ml_kem_768,
            "ml_kem_1024" => MLKemParameters.ml_kem_1024,
            _ => throw new ArgumentException($"Unsupported ML-KEM parameter set: {parameterName}", nameof(parameterName))
        };
    }
}
