using Org.BouncyCastle.Crypto.Kems;
using Org.BouncyCastle.Crypto.Parameters;

namespace Signal.Protocol.Demo;

/// <summary>
/// Maintains PQ ratchet state for a device pair.
/// </summary>
public sealed class PQRatchetState
{
    public PQRatchetKeyPair OurKeyPair { get; private set; }
    public PostQuantumPublicPreKey? RemotePublicKey { get; private set; }

    public PQRatchetState(PQRatchetKeyPair ourKeyPair, PostQuantumPublicPreKey? remotePublicKey)
    {
        OurKeyPair = ourKeyPair;
        RemotePublicKey = remotePublicKey;
    }

    public void RotateOurKeyPair(MLKemParameters parameters)
    {
        OurKeyPair = PQRatchetKeyPair.Generate(parameters);
    }

    public void SetRemotePublicKey(PostQuantumPublicPreKey publicKey)
    {
        RemotePublicKey = publicKey;
    }

    public (byte[] Ciphertext, byte[] SharedSecret) EncapsulateToRemote()
    {
        if (RemotePublicKey == null)
        {
            throw new System.InvalidOperationException("Remote PQ ratchet key is not set.");
        }

        var parameters = PostQuantumKeyManager.ResolveParameters(RemotePublicKey.Value.ParameterName);
        var publicKeyParameters = MLKemPublicKeyParameters.FromEncoding(parameters, RemotePublicKey.Value.PublicKey);

        var encapsulator = new MLKemEncapsulator(parameters);
        encapsulator.Init(publicKeyParameters);

        var ciphertext = new byte[encapsulator.EncapsulationLength];
        var secret = new byte[encapsulator.SecretLength];
        encapsulator.Encapsulate(ciphertext, 0, ciphertext.Length, secret, 0, secret.Length);

        return (ciphertext, secret);
    }

    public byte[] Decapsulate(byte[] ciphertext)
    {
        var parameters = PostQuantumKeyManager.ResolveParameters(OurKeyPair.ParameterName);
        var privateKeyParameters = MLKemPrivateKeyParameters.FromEncoding(parameters, OurKeyPair.PrivateKey);

        var decapsulator = new MLKemDecapsulator(parameters);
        decapsulator.Init(privateKeyParameters);

        var secret = new byte[decapsulator.SecretLength];
        decapsulator.Decapsulate(ciphertext, 0, ciphertext.Length, secret, 0, secret.Length);

        return secret;
    }
}
