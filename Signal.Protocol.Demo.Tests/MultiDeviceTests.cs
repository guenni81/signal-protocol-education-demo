namespace Signal.Protocol.Demo.Tests;

[Collection("TestCollection")]
public class MultiDeviceTests
{
    private readonly TestInfrastructure _infra;

    public MultiDeviceTests(TestInfrastructure infra)
    {
        _infra = infra;
        _infra.ResetState();
    }

    [Fact]
    public void Message_To_Multi_Device_User_Should_Be_Received_By_All_Devices()
    {
        // ARRANGE
        var bob = _infra.BobMobile;
        var aliceMobile = _infra.AliceMobile;
        var aliceTablet = _infra.AliceTablet;
        string message = "Hi Alice, this should reach both your devices!";

        // Bob must establish a session with BOTH of Alice's devices.
        // The demo implementation requires explicit session setup for each device pair.
        _infra.PairwiseMessageService.InitializeSession(bob, aliceMobile);
        _infra.PairwiseMessageService.InitializeSession(bob, aliceTablet);
        _infra.DeliverAllMessages();
        _infra.GetAndClearConsoleOutput();

        // ACT
        // Bob sends one message to the user "Alice". The test simulates fanning this out to all known devices.
        foreach (var aliceDevice in _infra.Alice.Devices)
        {
            _infra.PairwiseMessageService.SendMessage(bob, aliceDevice, message);
        }
        _infra.DeliverAllMessages();

        // ASSERT
        var output = _infra.GetAndClearConsoleOutput();
        
        // Check that both of Alice's devices received and decrypted the message.
        Assert.Contains($"  -> [{aliceMobile.Id}] processing 1:1 message from {bob.Id}: '{message}'", output);
        Assert.Contains($"  -> [{aliceTablet.Id}] processing 1:1 message from {bob.Id}: '{message}'", output);
    }
    
    [Fact]
    public void Message_From_Second_Device_Should_Be_Received()
    {
        // ARRANGE
        var bob = _infra.BobMobile;
        var aliceTablet = _infra.AliceTablet;
        string message = "Hello from my tablet!";

        // Initialize a session from Alice's TABLET to Bob
        _infra.PairwiseMessageService.InitializeSession(aliceTablet, bob);
        _infra.DeliverAllMessages();
        _infra.GetAndClearConsoleOutput();
        
        // ACT
        _infra.PairwiseMessageService.SendMessage(aliceTablet, bob, message);
        _infra.DeliverAllMessages();
        
        // ASSERT
        var output = _infra.GetAndClearConsoleOutput();
        Assert.Contains($"  -> [{bob.Id}] processing 1:1 message from {aliceTablet.Id}: '{message}'", output);
    }

}
