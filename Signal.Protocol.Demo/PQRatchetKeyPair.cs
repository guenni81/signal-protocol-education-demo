using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Security;

namespace Signal.Protocol.Demo;

/// <summary>
/// Represents an ML-KEM ratchet key pair for the Braid protocol.
/// Demo-only: stores private key bytes in memory.
/// </summary>
public sealed class PQRatchetKeyPair
{
    public byte[] PublicKey { get; }
    public byte[] PrivateKey { get; }
    public string ParameterName { get; }

    private PQRatchetKeyPair(byte[] publicKey, byte[] privateKey, string parameterName)
    {
        PublicKey = publicKey;
        PrivateKey = privateKey;
        ParameterName = parameterName;
    }

    public static PQRatchetKeyPair Generate(MLKemParameters parameters)
    {
        var generator = new MLKemKeyPairGenerator();
        generator.Init(new MLKemKeyGenerationParameters(new SecureRandom(), parameters));
        var pair = generator.GenerateKeyPair();

        var publicKey = ((MLKemPublicKeyParameters)pair.Public).GetEncoded();
        var privateKey = ((MLKemPrivateKeyParameters)pair.Private).GetEncoded();

        return new PQRatchetKeyPair(publicKey, privateKey, parameters.Name);
    }

    public static PQRatchetKeyPair FromPreKey(PostQuantumPreKey preKey)
    {
        return new PQRatchetKeyPair(preKey.PublicKey, preKey.PrivateKey, preKey.ParameterName);
    }

    public PostQuantumPublicPreKey ToPublicPreKey()
    {
        return new PostQuantumPublicPreKey(
            KeyId: System.Convert.ToBase64String(PublicKey),
            PublicKey: PublicKey,
            ParameterName: ParameterName);
    }
}
