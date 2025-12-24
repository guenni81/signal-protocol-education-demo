using NSec.Cryptography;
using System.Collections.Concurrent;
using System.Collections.Generic;

namespace Signal.Protocol.Demo;

/// <summary>
/// Simulates a server that stores and delivers public Pre-Key bundles for each DEVICE.
/// </summary>
public class PreKeyServer
{
    // The keys of the dictionaries are now the unique device IDs.
    private readonly Dictionary<string, (PublicKey SigningKey, PublicKey AgreementKey)> _identityKeys = new();
    private readonly Dictionary<string, (PublicKey Key, byte[] Signature)> _signedPreKeys = new();
    private readonly Dictionary<string, ConcurrentQueue<(string KeyId, PublicKey Key)>> _oneTimePreKeys = new();

    /// <summary>
    /// FOR TESTING: Clears all keys from the server.
    /// </summary>
    public void ClearKeys()
    {
        _identityKeys.Clear();
        _signedPreKeys.Clear();
        _oneTimePreKeys.Clear();
    }

    /// <summary>
    /// Uploads the keys of a specific device to the server.
    /// </summary>
    /// <param name="device">The device whose keys are being uploaded.</param>
    public void UploadDeviceKeys(Device device)
    {
        _identityKeys[device.Id] = (device.KeyManager.IdentitySigningKey.PublicKey, device.KeyManager.IdentityAgreementKey.PublicKey);
        _signedPreKeys[device.Id] = (device.KeyManager.SignedPreKey.PublicKey, device.KeyManager.SignedPreKeySignature);
        
        var deviceOneTimeKeysQueue = new ConcurrentQueue<(string KeyId, PublicKey Key)>();
        var deviceOneTimeKeysDict = device.KeyManager.GetPublicOneTimePreKeys();
        foreach (var pair in deviceOneTimeKeysDict)
        {
            deviceOneTimeKeysQueue.Enqueue((pair.Key, pair.Value));
        }
        _oneTimePreKeys[device.Id] = deviceOneTimeKeysQueue;
    }

    /// <summary>
    /// Retrieves the Pre-Key bundle for a specific device.
    /// </summary>
    /// <param name="deviceId">The ID of the device for which the bundle is being retrieved.</param>
    /// <returns>The PreKeyBundle, or null if the device was not found.</returns>
    public PreKeyBundle? GetPreKeyBundle(string deviceId)
    {
        if (!_identityKeys.ContainsKey(deviceId)) return null;

        var (publicIdentitySigningKey, publicIdentityAgreementKey) = _identityKeys[deviceId];
        var (publicSignedPreKey, signedPreKeySignature) = _signedPreKeys[deviceId];

        // Try to retrieve a One-Time PreKey. If none are left, that's also fine.
        (string KeyId, PublicKey Key)? oneTimePreKey = null;
        if (_oneTimePreKeys.TryGetValue(deviceId, out var deviceOtpQueue) && deviceOtpQueue.TryDequeue(out var otp))
        {
            oneTimePreKey = otp;
        }

        return new PreKeyBundle(
            deviceId,
            publicIdentitySigningKey,
            publicIdentityAgreementKey,
            publicSignedPreKey,
            signedPreKeySignature,
            oneTimePreKey);
    }
}
