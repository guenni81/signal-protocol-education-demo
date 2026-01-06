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

    [Fact]
    public void OutOfOrder_After_Ratchet_Should_Defer_Until_PqCiphertext_Arrives()
    {
        // ARRANGE
        InitializeSession();
        DebugMode.Enabled = true;
        var alice = _infra.AliceMobile;
        var bob = _infra.BobMobile;

        // Seed the conversation so Bob has a receiving chain.
        _infra.PairwiseMessageService.SendMessage(alice, bob, "Seed-1");
        _infra.DeliverAllMessages();
        _infra.GetAndClearConsoleOutput();

        // Bob replies so Alice performs a ratchet step and prepares PQ ciphertext.
        _infra.PairwiseMessageService.SendMessage(bob, alice, "Seed-2");
        _infra.DeliverAllMessages();
        _infra.GetAndClearConsoleOutput();

        // Alice sends two messages on the new sending chain.
        string msg1 = "PostRatchet-1";
        string msg2 = "PostRatchet-2";
        _infra.PairwiseMessageService.SendMessage(alice, bob, msg1);
        _infra.PairwiseMessageService.SendMessage(alice, bob, msg2);

        // ACT: deliver second (no PQ ciphertext) before first (with PQ ciphertext).
        _infra.TransportService.DeliverMessagesToDevice(bob.Id, new() { 1, 0 });

        // ASSERT
        var output = _infra.GetAndClearConsoleOutput();
        Assert.Contains($"  -> [{bob.Id}] processing 1:1 message from {alice.Id}: '{msg1}'", output);
        Assert.Contains($"  -> [{bob.Id}] processing 1:1 message from {alice.Id}: '{msg2}'", output);
    }

    [Fact]
    public void OldChain_Message_Should_Decrypt_After_New_Ratchet_Message()
    {
        // ARRANGE
        InitializeSession();
        DebugMode.Enabled = true;
        var alice = _infra.AliceMobile;
        var bob = _infra.BobMobile;
        string msg1 = "Chain-A-1";
        string msg2 = "Chain-A-2";
        string msg3 = "Chain-B-1";

        // Alice sends two messages; deliver only the first.
        _infra.PairwiseMessageService.SendMessage(alice, bob, msg1);
        _infra.PairwiseMessageService.SendMessage(alice, bob, msg2);
        _infra.TransportService.DeliverMessagesToDevice(bob.Id, new() { 0 });
        _infra.GetAndClearConsoleOutput();

        // Bob replies so Alice performs a ratchet step.
        _infra.PairwiseMessageService.SendMessage(bob, alice, "Bob-Reply");
        _infra.TransportService.DeliverMessagesToDevice(alice.Id, new() { 0 });
        _infra.GetAndClearConsoleOutput();

        // Alice sends a message on the new chain.
        _infra.PairwiseMessageService.SendMessage(alice, bob, msg3);

        // ACT: deliver new-chain message before old-chain message.
        _infra.TransportService.DeliverMessagesToDevice(bob.Id, new() { 1, 0 });

        // ASSERT
        var output = _infra.GetAndClearConsoleOutput();
        Assert.Contains($"  -> [{bob.Id}] processing 1:1 message from {alice.Id}: '{msg3}'", output);
        Assert.Contains($"  -> [{bob.Id}] processing 1:1 message from {alice.Id}: '{msg2}'", output);
    }

    [Fact]
    public void Header_Tampering_Should_Fail_Decryption()
    {
        // ARRANGE
        InitializeSession();
        DebugMode.Enabled = false;
        var alice = _infra.AliceMobile;
        var bob = _infra.BobMobile;

        var senderRatchet = alice.PairwiseSessions[bob.Id];
        var receiverRatchet = bob.PairwiseSessions[alice.Id];

        var seed = senderRatchet.RatchetEncrypt(System.Text.Encoding.UTF8.GetBytes("Seed"));
        var seedPlaintext = receiverRatchet.RatchetDecrypt(seed);
        Assert.NotNull(seedPlaintext);

        var message = senderRatchet.RatchetEncrypt(System.Text.Encoding.UTF8.GetBytes("Payload"));
        var tampered = new EncryptedMessage(
            message.SenderRatchetKey,
            message.MessageNumber + 1,
            message.PreviousMessageNumber,
            message.Ciphertext,
            message.PostQuantumCiphertext,
            message.SenderPostQuantumRatchetKey);

        // ACT
        var plaintext = receiverRatchet.RatchetDecrypt(tampered);

        // ASSERT
        Assert.Null(plaintext);
    }
    
}
