namespace Signal.Protocol.Demo.Logging;

/// <summary>
/// Defines the categories for trace logging to structure the output
/// and facilitate understanding of the Signal Protocol flow.
/// </summary>
public enum TraceCategory
{
    /// <summary>
    /// Relates to the generation of keys (Identity, PreKeys).
    /// </summary>
    KEYGEN,
    
    /// <summary>
    /// Relates to the X3DH handshake for session initialization.
    /// </summary>
    X3DH,
    
    /// <summary>
    /// Relates to the state and operations of the Double Ratchet (1:1 communication).
    /// </summary>
    RATCHET,
    
    /// <summary>
    /// Relates to operations with Sender Keys for group chats.
    /// </summary>
    GROUP,
    
    /// <summary>
    /// Relates to the specific handling of out-of-order messages,
    /// storing of skipped keys, and replay detection.
    /// </summary>
    ORDERING,
    
    /// <summary>
    /// General messages describing the application flow.
    /// </summary>
    INFO
}