namespace Signal.Protocol.Demo.Tests;

[Collection("TestCollection")]
public class KeyManagementTests
{
    private readonly TestInfrastructure _infra;

    public KeyManagementTests(TestInfrastructure infra)
    {
        _infra = infra;
        _infra.ResetState();
    }

    [Fact]
    public void Device_Should_Have_Valid_IdentityKey()
    {
        // ARRANGE
        var device = _infra.AliceMobile;

        // ASSERT
        Assert.NotNull(device.KeyManager.IdentitySigningKey);
        Assert.NotNull(device.KeyManager.IdentitySigningKey.PublicKey);
    }

    [Fact]
    public void Device_Should_Have_Valid_SignedPreKey()
    {
        // ARRANGE
        var device = _infra.AliceMobile;

        // ASSERT
        Assert.NotNull(device.KeyManager.SignedPreKey);
        Assert.NotNull(device.KeyManager.SignedPreKey.PublicKey);
        Assert.NotNull(device.KeyManager.SignedPreKeySignature);
        Assert.NotEmpty(device.KeyManager.SignedPreKeySignature);
    }

    [Fact]
    public void Device_Should_Have_Multiple_OneTimePreKeys()
    {
        // ARRANGE
        var device = _infra.AliceMobile;

        // ASSERT
        var oneTimeKeys = device.KeyManager.GetPublicOneTimePreKeys();
        Assert.NotNull(oneTimeKeys);
        Assert.Equal(10, oneTimeKeys.Count); // Check for a reasonable number
        
        var firstKey = oneTimeKeys.First();
        Assert.NotNull(firstKey.Value);
    }

    [Fact]
    public void PreKeyServer_Should_Contain_Uploaded_Keys()
    {
        // ARRANGE
        var device = _infra.AliceMobile;
        var server = _infra.PreKeyServer;

        // ACT
        // Keys are uploaded in TestInfrastructure constructor

        // ASSERT
        var bundle = server.GetPreKeyBundle(device.Id);
        Assert.NotNull(bundle);
        Assert.Equal(device.KeyManager.IdentityAgreementKey.PublicKey.Export(NSec.Cryptography.KeyBlobFormat.RawPublicKey), bundle.PublicIdentityAgreementKey.Export(NSec.Cryptography.KeyBlobFormat.RawPublicKey));
        Assert.Equal(device.KeyManager.SignedPreKey.PublicKey.Export(NSec.Cryptography.KeyBlobFormat.RawPublicKey), bundle.PublicSignedPreKey.Export(NSec.Cryptography.KeyBlobFormat.RawPublicKey));
        Assert.NotNull(bundle.PublicOneTimePreKey);
    }

    [Fact]
    public void TakeOneTimePreKey_Should_Remove_Key_From_Bundle()
    {
        // ARRANGE
        var device = _infra.BobMobile;
        var server = _infra.PreKeyServer;
        
        var initialBundle = server.GetPreKeyBundle(device.Id);
        Assert.NotNull(initialBundle);
        Assert.NotNull(initialBundle.PublicOneTimePreKeyId);

        // ACT
        // The key is "taken" by the server when requested, so we just request another one.
        var subsequentBundle = server.GetPreKeyBundle(device.Id);

        // ASSERT
        Assert.NotNull(subsequentBundle);
        Assert.NotNull(subsequentBundle.PublicOneTimePreKeyId);
        // The next bundle should have a DIFFERENT one-time key ID
        Assert.NotEqual(initialBundle.PublicOneTimePreKeyId, subsequentBundle.PublicOneTimePreKeyId);
    }
}
