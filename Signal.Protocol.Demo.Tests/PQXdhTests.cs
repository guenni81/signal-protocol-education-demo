namespace Signal.Protocol.Demo.Tests;

[Collection("TestCollection")]
public class PQXdhTests
{
    private readonly TestInfrastructure _infra;

    public PQXdhTests(TestInfrastructure infra)
    {
        _infra = infra;
        _infra.ResetState();
    }

    [Fact]
    public void InitiateSession_Should_Fail_When_PqPreKeySignature_Is_Tampered()
    {
        // ARRANGE
        var alice = _infra.AliceMobile;
        var bob = _infra.BobMobile;
        var bundle = _infra.PreKeyServer.GetPreKeyBundle(bob.Id);

        Assert.NotNull(bundle);
        Assert.NotNull(bundle.PublicPostQuantumPreKey);
        Assert.NotNull(bundle.PublicPostQuantumPreKeySignature);

        var tamperedSignature = (byte[])bundle.PublicPostQuantumPreKeySignature.Clone();
        tamperedSignature[0] ^= 0xFF;

        var tamperedBundle = new PreKeyBundle(
            bundle.DeviceId,
            bundle.PublicIdentitySigningKey,
            bundle.PublicIdentityAgreementKey,
            bundle.PublicSignedPreKey,
            bundle.SignedPreKeySignature,
            bundle.PublicOneTimePreKeyId != null && bundle.PublicOneTimePreKey != null
                ? (bundle.PublicOneTimePreKeyId, bundle.PublicOneTimePreKey)
                : null,
            bundle.PublicPostQuantumPreKey,
            tamperedSignature,
            postQuantumOneTimePreKey: null);

        // ACT
        var ex = Assert.Throws<InvalidOperationException>(() =>
            PQXdhSession.InitiateSession(alice, tamperedBundle));

        // ASSERT
        Assert.Contains("Invalid PQ prekey signature", ex.Message);
    }
}
