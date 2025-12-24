namespace Signal.Protocol.Demo.Tests;

[Collection("TestCollection")]
public class DoubleRatchetTests
{
    private readonly TestInfrastructure _infra;

    public DoubleRatchetTests(TestInfrastructure infra)
    {
        _infra = infra;
        _infra.ResetState();
    }

    private void InitializeSession()
    {
        _infra.PairwiseMessageService.InitializeSession(_infra.AliceMobile, _infra.BobMobile);
        _infra.DeliverAllMessages();
        _infra.GetAndClearConsoleOutput(); // Clear session init logs
    }

    [Fact]
    public void SendMessage_Should_Be_Received_And_Decrypted()
    {
        // ARRANGE
        InitializeSession();
        DebugMode.Enabled = true;
        var alice = _infra.AliceMobile;
        var bob = _infra.BobMobile;
        string message = "Hello, Bob!";

        // ACT
        _infra.PairwiseMessageService.SendMessage(alice, bob, message);
        _infra.DeliverAllMessages();

        // ASSERT
        var output = _infra.GetAndClearConsoleOutput();
        Assert.Contains($"  -> [{bob.Id}] processing 1:1 message from {alice.Id}: '{message}'", output);
    }

    [Fact]
    public void Conversation_Should_Flow_Back_And_Forth()
    {
        // ARRANGE
        InitializeSession();
        DebugMode.Enabled = true;
        var alice = _infra.AliceMobile;
        var bob = _infra.BobMobile;
        string msg1_A = "Hi Bob!";
        string msg2_B = "Hi Alice! Got your message.";
        string msg3_A = "Great!";

        // ACT & ASSERT
        // 1. Alice -> Bob
        _infra.PairwiseMessageService.SendMessage(alice, bob, msg1_A);
        _infra.DeliverAllMessages();
        var output1 = _infra.GetAndClearConsoleOutput();
        Assert.Contains($"  -> [{bob.Id}] processing 1:1 message from {alice.Id}: '{msg1_A}'", output1);

        // 2. Bob -> Alice
        _infra.PairwiseMessageService.SendMessage(bob, alice, msg2_B);
        _infra.DeliverAllMessages();
        var output2 = _infra.GetAndClearConsoleOutput();
        Assert.Contains($"  -> [{alice.Id}] processing 1:1 message from {bob.Id}: '{msg2_B}'", output2);
        
        // 3. Alice -> Bob
        _infra.PairwiseMessageService.SendMessage(alice, bob, msg3_A);
        _infra.DeliverAllMessages();
        var output3 = _infra.GetAndClearConsoleOutput();
        Assert.Contains($"  -> [{bob.Id}] processing 1:1 message from {alice.Id}: '{msg3_A}'", output3);
    }
    
    [Fact]
    public void OutOfOrder_Messages_Should_Be_Decrypted()
    {
        // ARRANGE
        InitializeSession();
        DebugMode.Enabled = true;
        var alice = _infra.AliceMobile;
        var bob = _infra.BobMobile;
        string msg1 = "First";
        string msg2 = "Second";
        string msg3 = "Third";

        // ACT
        // 1. Alice sends three messages
        _infra.PairwiseMessageService.SendMessage(alice, bob, msg1);
        _infra.PairwiseMessageService.SendMessage(alice, bob, msg2);
        _infra.PairwiseMessageService.SendMessage(alice, bob, msg3);
        
        // 2. Deliver them out of order (3, then 1, then 2)
        _infra.TransportService.DeliverMessagesToDevice(bob.Id, new() { 2, 0, 1 });

        // ASSERT
        var output = _infra.GetAndClearConsoleOutput();
        // The current implementation does not explicitly log buffering, so we only check for final decryption.
        // Check that all messages were ultimately decrypted
        Assert.Contains($"  -> [{bob.Id}] processing 1:1 message from {alice.Id}: '{msg1}'", output);
        Assert.Contains($"  -> [{bob.Id}] processing 1:1 message from {alice.Id}: '{msg2}'", output);
        Assert.Contains($"  -> [{bob.Id}] processing 1:1 message from {alice.Id}: '{msg3}'", output);
    }
    
}

