using System;
using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Security;

namespace Signal.Protocol.Demo;

/// <summary>
/// Represents an ML-KEM (Kyber) Post-Quantum PreKey with encoded key material.
/// Demo-only: this stores private keys in memory for illustration.
/// </summary>
public sealed class PostQuantumPreKey
{
    public string KeyId { get; }
    public byte[] PublicKey { get; }
    public byte[] PrivateKey { get; }
    public string ParameterName { get; }

    private PostQuantumPreKey(string keyId, byte[] publicKey, byte[] privateKey, string parameterName)
    {
        KeyId = keyId;
        PublicKey = publicKey;
        PrivateKey = privateKey;
        ParameterName = parameterName;
    }

    public static PostQuantumPreKey Generate(MLKemParameters parameters)
    {
        var generator = new MLKemKeyPairGenerator();
        generator.Init(new MLKemKeyGenerationParameters(new SecureRandom(), parameters));

        var pair = generator.GenerateKeyPair();
        var publicKey = ((MLKemPublicKeyParameters)pair.Public).GetEncoded();
        var privateKey = ((MLKemPrivateKeyParameters)pair.Private).GetEncoded();
        var keyId = Convert.ToBase64String(publicKey);
        var parameterName = parameters.Name;

        return new PostQuantumPreKey(keyId, publicKey, privateKey, parameterName);
    }

    public PostQuantumPublicPreKey ToPublic()
    {
        return new PostQuantumPublicPreKey(KeyId, PublicKey, ParameterName);
    }
}

/// <summary>
/// Represents a public-only ML-KEM PreKey that can be uploaded to the server.
/// </summary>
public readonly record struct PostQuantumPublicPreKey(string KeyId, byte[] PublicKey, string ParameterName);
