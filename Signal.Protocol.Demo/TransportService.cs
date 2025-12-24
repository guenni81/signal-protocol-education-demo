using System;
using System.Collections.Generic;
using System.Linq;

namespace Signal.Protocol.Demo;

/// <summary>
/// Encapsulates a message that is "in transit", including its recipient and content.
/// </summary>
public class PendingMessage
{
    public Device Recipient { get; }
    public string SenderId { get; }
    public object Message { get; } // Can be EncryptedMessage or GroupMessage

    public PendingMessage(Device recipient, string senderId, object message)
    {
        Recipient = recipient;
        SenderId = senderId;
        Message = message;
    }
}

/// <summary>
/// Simulates a network transport layer that can hold messages and deliver them
/// in any order. This is key to simulating out-of-order delivery.
/// </summary>
public class TransportService
{
    private readonly MessageService _pairwiseMessageService;
    private readonly GroupMessageService _groupMessageService;
    
    // A list that holds all messages currently "on the network".
    private readonly List<PendingMessage> _messageQueue = new();

    public TransportService(MessageService pairwiseMessageService, GroupMessageService groupMessageService)
    {
        _pairwiseMessageService = pairwiseMessageService;
        _groupMessageService = groupMessageService;
    }

    /// <summary>
    /// FOR TESTING: Clears all messages from the queue.
    /// </summary>
    public void ClearAllMessages()
    {
        _messageQueue.Clear();
    }

    /// <summary>
    /// Queues a message instead of delivering it immediately.
    /// </summary>
    public void QueueMessage(Device recipient, string senderId, object message)
    {
        TraceLogger.Log(TraceCategory.INFO, $"      [Transport] Message from {senderId} to {recipient.Id} has been queued.");
        _messageQueue.Add(new PendingMessage(recipient, senderId, message));
    }
    
    /// <summary>
    /// Queues a group message for delivery to all relevant recipients.
    /// </summary>
    public void QueueGroupMessage(GroupMessage groupMessage, IEnumerable<Device> recipients)
    {
        var recipientList = recipients.ToList();
        TraceLogger.Log(TraceCategory.INFO, $"      [Transport] Group message from {groupMessage.SenderDeviceId} queued for {recipientList.Count} recipients.");
        foreach (var recipient in recipientList)
        {
            // Each device gets its own copy of the message in the queue
            _messageQueue.Add(new PendingMessage(recipient, groupMessage.SenderDeviceId, groupMessage));
        }
    }

    /// <summary>
    /// Delivers a subset of messages in a specific order to a specific device.
    /// </summary>
    /// <param name="recipientId">The ID of the target device.</param>
    /// <param name="deliveryOrder">
    /// A list of indices that defines the delivery order.
    /// IMPORTANT: The indices refer to the list of messages intended *only for this recipient*,
    /// not the global queue.
    /// </param>
    public void DeliverMessagesToDevice(string recipientId, List<int> deliveryOrder)
    {
        TraceLogger.Log(TraceCategory.INFO, $"\n>>>>> Delivering to {recipientId} in custom order: {string.Join(", ", deliveryOrder.Select(i => i + 1))}...");
        
        // Find all messages intended for this device
        var recipientMessages = _messageQueue.Where(m => m.Recipient.Id == recipientId).ToList();
        var messagesToDeliver = new List<PendingMessage>();

        foreach (var index in deliveryOrder)
        {
            if (index < recipientMessages.Count)
            {
                var pendingMessage = recipientMessages[index];
                messagesToDeliver.Add(pendingMessage);
            }
        }
        
        foreach (var pendingMessage in messagesToDeliver)
        {
            TraceLogger.Log(TraceCategory.INFO, $"  -> Delivering message (Sender: {pendingMessage.SenderId})");
            Deliver(pendingMessage);
            _messageQueue.Remove(pendingMessage); // Remove from the global queue
        }
    }
    
    /// <summary>
    /// Delivers all remaining messages in the queue in their original order.
    /// Useful for completing setup phases or cleaning up the simulation.
    /// </summary>
    public void DeliverAllQueuedMessages()
    {
        if (_messageQueue.Count == 0) return;
        
        TraceLogger.Log(TraceCategory.INFO, $"\n>>>>> Delivering all remaining {_messageQueue.Count} messages in the queue...");
        // Create a copy, as the original queue will be modified during iteration.
        var queueCopy = new List<PendingMessage>(_messageQueue);
        
        foreach (var pendingMessage in queueCopy)
        {
            // Ensure the message is still in the main queue, in case it was already
            // removed as part of another delivery in a previous step of this method.
            if (_messageQueue.Contains(pendingMessage))
            {
                 TraceLogger.Log(TraceCategory.INFO, $"  -> Delivering to {pendingMessage.Recipient.Id} (Sender: {pendingMessage.SenderId})");
                 Deliver(pendingMessage);
                 _messageQueue.Remove(pendingMessage);
            }
        }
    }

    /// <summary>
    /// Private helper function that forwards a single message to the appropriate service for processing.
    /// </summary>
    private void Deliver(PendingMessage pendingMessage)
    {
        if (pendingMessage.Message is EncryptedMessage pairwiseMsg)
        {
            // A 1:1 message is processed directly by the MessageService
            _pairwiseMessageService.ReceiveMessage(pendingMessage.Recipient, pendingMessage.SenderId, pairwiseMsg);
        }
        else if (pendingMessage.Message is GroupMessage groupMsg)
        {
            // A group message is processed by the GroupMessageService
            _groupMessageService.ReceiveGroupMessage(pendingMessage.Recipient, groupMsg);
        }
    }
}