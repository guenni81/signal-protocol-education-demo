using System.Linq;

namespace Signal.Protocol.Demo.Tests;

[Collection("TestCollection")]
public class X3DHTests
{
    private readonly TestInfrastructure _infra;

    public X3DHTests(TestInfrastructure infra)
    {
        _infra = infra;
        _infra.ResetState();
    }

    [Fact]
    public void InitializeSession_Should_Establish_Pairwise_DoubleRatchets()
    {
        // ARRANGE
        DebugMode.Enabled = true;
        var alice = _infra.AliceMobile;
        var bob = _infra.BobMobile;

        // Ensure no sessions exist beforehand
        Assert.Empty(alice.PairwiseSessions);
        Assert.Empty(bob.PairwiseSessions);

        // ACT
        // The MessageService orchestrates the entire X3DH handshake.
        _infra.PairwiseMessageService.InitializeSession(alice, bob);
        
        // The handshake involves sending an initial message, which we must now deliver.
        _infra.DeliverAllMessages();

        // ASSERT
        // 1. Verify Alice has a session for Bob.
        Assert.True(alice.PairwiseSessions.ContainsKey(bob.Id));
        Assert.NotNull(alice.PairwiseSessions[bob.Id]);
        
        // 2. Verify Bob has a session for Alice.
        Assert.True(bob.PairwiseSessions.ContainsKey(alice.Id));
        Assert.NotNull(bob.PairwiseSessions[alice.Id]);
        
        // 3. Check logs to see the X3DH exchange happen (optional but good sanity check)
        var output = _infra.GetAndClearConsoleOutput();
        Assert.Contains("[X3DH    ]", output);
        Assert.Contains($">>> Initializing 1:1 session: {alice.Id} -> {bob.Id}", output);
    }
    
}
