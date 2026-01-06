namespace Signal.Protocol.Demo;

/// <summary>
/// Represents a Post-Quantum ML-KEM PreKey bundle for a specific device.
/// Demo-only: contains only public keys suitable for upload.
/// </summary>
public sealed class PostQuantumPreKeyBundle
{
    public string DeviceId { get; }
    public PostQuantumPublicPreKey PublicPreKey { get; }
    public PostQuantumPublicPreKey? PublicOneTimePreKey { get; }

    public PostQuantumPreKeyBundle(
        string deviceId,
        PostQuantumPublicPreKey publicPreKey,
        PostQuantumPublicPreKey? publicOneTimePreKey)
    {
        DeviceId = deviceId;
        PublicPreKey = publicPreKey;
        PublicOneTimePreKey = publicOneTimePreKey;
    }
}
