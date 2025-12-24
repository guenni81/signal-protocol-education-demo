namespace Signal.Protocol.Demo.Tests;

[Collection("TestCollection")]
public class EdgeCaseTests
{
    private readonly TestInfrastructure _infra;

    public EdgeCaseTests(TestInfrastructure infra)
    {
        _infra = infra;
        _infra.ResetState();
    }

    
    [Fact]
    public void SessionInit_Should_Succeed_When_OneTimePreKeys_Are_Exhausted()
    {
        // ARRANGE
        var alice = _infra.AliceMobile;
        var bob = _infra.BobMobile;
        DebugMode.Enabled = true;

        var server = _infra.PreKeyServer;
        // Exhaust all of Bob's one-time pre-keys by repeatedly fetching them.
        while (true)
        {
            var bundle = server.GetPreKeyBundle(bob.Id);
            if (bundle == null || bundle.PublicOneTimePreKeyId == null)
            {
                break; // No more keys
            }
        }
        
        // Verify they are gone
        var finalBundle = server.GetPreKeyBundle(bob.Id);
        Assert.NotNull(finalBundle);
        Assert.Null(finalBundle.PublicOneTimePreKeyId);
        _infra.GetAndClearConsoleOutput();
        
        // ACT
        // Alice now initializes a session. The handshake should proceed without the one-time key.
        _infra.PairwiseMessageService.InitializeSession(alice, bob);
        _infra.DeliverAllMessages();
        
        // ASSERT
        var output = _infra.GetAndClearConsoleOutput();
        
        // Check that the handshake completed successfully and derived a secret,
        // even without a one-time key.
        Assert.Contains("[X3DH    ]", output);
        Assert.Contains("Proceeding with X3DH without a one-time pre-key.", output);
        
        // Verify sessions were still established.
        Assert.True(alice.PairwiseSessions.ContainsKey(bob.Id));
        Assert.True(bob.PairwiseSessions.ContainsKey(alice.Id));
    }
}
