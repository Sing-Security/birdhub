// ============================================================================
// MUX MODULE: many streams over one Temper session
// ============================================================================
//
// One session between two nodes carries many conversations at once. Each
// conversation is a *stream*: a client opens one per accepted local
// connection, a serving node is handed one per incoming request, and the hub
// pairs streams from two sessions when it relays between nodes that cannot
// reach each other directly.
//
// The wire messages are `RelayMessage` (relay.rs), each carrying a stream id.
// This module owns the multiplexing: a driver task holds one session's two
// halves and a table of open streams, and hands tasks a `Substream` that
// behaves like a byte stream — `AsyncRead` + `AsyncWrite` — so the same relay
// pump that copies bytes for a TCP connection copies bytes for a stream
// without knowing the difference.
//
// Three choices worth stating, because each has a cost:
//
//   - **Backpressure, not buffering.** When a stream's reader is slow its
//     channel fills, the driver blocks on the send, and the whole session
//     stalls. That is head-of-line blocking, chosen over the alternative:
//     unbounded per-stream buffers turn one slow reader into an OOM on the
//     peer. The direct carrier (QUIC) has per-stream flow control and is
//     where throughput belongs; this path is the fallback.
//   - **Both sides may open.** Stream ids are allocated with a per-side
//     parity — the session's initiator takes odd ids, the responder even — so
//     a serving node can dial back over the same session without colliding.
//     This is the QUIC convention, borrowed because it works.
//   - **Half-close and abort are different messages.** `Close` means "no more
//     bytes from me", the shape `nc -N` and HTTP/1.0 produce; `Reset` means
//     "drop this stream now". The pump relies on the distinction, and a
//     dropped `Substream` sends whichever one is true at drop time.

use crate::error::{Error, Result};
use crate::relay::{MessageRx, MessageTx, RelayMessage};
use std::collections::HashMap;
use std::pin::Pin;
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll, Waker};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::sync::{mpsc, oneshot};

/// Chunks buffered per stream, per direction. At the relay's 64 KiB chunk
/// this bounds one stream at a megabyte of in-flight memory and bounds the
/// driver's tolerance of a slow reader before the session stalls.
const STREAM_QUEUE: usize = 16;

/// Chunks buffered for commands *into* the driver. Small on purpose:
/// reaching it means a writer is producing faster than the session drains,
/// and the right answer there is to park the writer, not to grow a queue.
const COMMAND_QUEUE: usize = 16;

/// Streams that may be open but unanswered before the driver stops reading
/// the session. Bounds what an application that stops calling `accept` can
/// make the driver hold.
const ACCEPT_QUEUE: usize = 16;

// region:    --- Commands

/// Everything a task can ask the driver to do.
enum Command {
    /// Open a stream and wait for the peer's answer.
    Open {
        stream: u32,
        target: String,
        reply: oneshot::Sender<Result<Substream>>,
    },
    /// Answer an inbound `Open`, once the application has decided.
    Answer {
        stream: u32,
        result: std::result::Result<(), String>,
    },
    Data {
        stream: u32,
        bytes: Vec<u8>,
    },
    /// Half-close: no more data from this side.
    Close {
        stream: u32,
    },
    /// Abort: this side is gone; drop the stream at both ends.
    Reset {
        stream: u32,
    },
    /// This side is finished with the stream and nothing needs saying on the
    /// wire — drop the local bookkeeping. Sent after `Close` at the end of a
    /// normal stream, so a long-lived session does not accumulate an entry
    /// per conversation it has ever carried.
    Done {
        stream: u32,
    },
    /// End the whole session now: the driver stops reading the wire and drops
    /// both halves, which closes the socket and ends every stream. The
    /// operator's kick (control.rs), and the node's reconnect — where the
    /// supervisor's retirement of the old session is exactly this, from the
    /// inside.
    Shutdown,
}

// endregion: --- Commands

// region:    --- Handle

/// The cloneable half: every connection task clones one to open streams.
#[derive(Clone)]
pub struct Mux {
    commands: mpsc::Sender<Command>,
    next_stream: Arc<AtomicU32>,
}

impl Mux {
    /// Open a stream to `target`, waiting for the peer's answer.
    ///
    /// `Err` is the peer's refusal — a grant, a failed dial — carrying the
    /// reason it gave. That refusal is the entire vocabulary the dialing side
    /// gets, deliberately: it is why a refused target must never be dialed
    /// before being refused (nothing about the peer's reachable network can
    /// be learned by timing a refusal).
    pub async fn open(&self, target: &str) -> Result<Substream> {
        let stream = self.next_stream.fetch_add(2, Ordering::Relaxed);
        let (reply_tx, reply_rx) = oneshot::channel();
        self.commands
            .send(Command::Open {
                stream,
                target: target.to_string(),
                reply: reply_tx,
            })
            .await
            .map_err(|_| Error::custom("session closed before the stream could open"))?;

        reply_rx
            .await
            .map_err(|_| Error::custom("session closed while opening the stream"))?
    }

    /// Whether the driver is gone — the session ended, cleanly or not.
    ///
    /// A caller that gets an error from `open` on a closed session should
    /// reconnect and try once more; a caller that gets a refusal on a live
    /// session should report it. This is how the two are told apart.
    pub fn is_closed(&self) -> bool {
        self.commands.is_closed()
    }

    /// Close the whole session now — the operator's kick.
    ///
    /// The driver ends on the command, dropping the socket halves and every
    /// stream with them: readers see EOF, pending `open`s are told the
    /// session closed, and the peer's driver ends on the same EOF. A later
    /// call on an already-dead session is a no-op, which is what makes it
    /// safe for two kickers (the board's entry and the registry's handle)
    /// to race.
    pub fn shutdown(&self) {
        let _ = self.commands.try_send(Command::Shutdown);
    }
}

// endregion: --- Handle

// region:    --- Session

/// One session's multiplexed endpoint, plus the queue of inbound streams
/// only this object may take from.
///
/// The split from [`Mux`] is load-bearing: exactly one task may accept, and
/// the type says so instead of a comment — clones taken with [`handle`] can
/// open but cannot accept.
///
/// [`handle`]: Self::handle
pub struct MuxSession {
    mux: Mux,
    incoming: mpsc::Receiver<IncomingStream>,
}

impl MuxSession {
    /// Multiplex a session this side initiated: odd stream ids.
    ///
    /// Constructors are crate-internal on purpose: a frontend reads sessions
    /// through the hub's board and the node's link, and never builds one, so
    /// the traits the mux is generic over stay out of the public API.
    pub(crate) fn initiator<T, R>(tx: T, rx: R) -> Self
    where
        T: MessageTx + Send + 'static,
        R: MessageRx + Send + 'static,
    {
        Self::spawn(tx, rx, 1)
    }

    /// Multiplex a session this side accepted: even stream ids.
    pub(crate) fn responder<T, R>(tx: T, rx: R) -> Self
    where
        T: MessageTx + Send + 'static,
        R: MessageRx + Send + 'static,
    {
        Self::spawn(tx, rx, 2)
    }

    /// The cloneable half, for tasks that open streams.
    pub fn handle(&self) -> Mux {
        self.mux.clone()
    }

    /// The next inbound stream, or `None` once the session is gone.
    pub async fn accept(&mut self) -> Option<IncomingStream> {
        self.incoming.recv().await
    }

    fn spawn<T, R>(tx: T, rx: R, first_stream: u32) -> Self
    where
        T: MessageTx + Send + 'static,
        R: MessageRx + Send + 'static,
    {
        let (commands_tx, commands_rx) = mpsc::channel(COMMAND_QUEUE);
        let (incoming_tx, incoming_rx) = mpsc::channel(ACCEPT_QUEUE);
        let writers: Arc<Mutex<Vec<Waker>>> = Arc::new(Mutex::new(Vec::new()));

        let driver = Driver {
            tx,
            rx,
            commands_tx: commands_tx.clone(),
            commands_rx,
            incoming_tx,
            writers: writers.clone(),
            streams: HashMap::new(),
            ended: false,
        };
        tokio::spawn(driver.run());

        Self {
            mux: Mux {
                commands: commands_tx,
                next_stream: Arc::new(AtomicU32::new(first_stream)),
            },
            incoming: incoming_rx,
        }
    }
}

// endregion: --- Session

// region:    --- Driver

/// What one driver iteration produced.
enum Event {
    Command(Command),
    Message(RelayMessage),
    /// The session ended, either cleanly or not. Every stream ends here.
    Ended,
}

struct Driver<T, R> {
    tx: T,
    rx: R,
    /// Kept alongside the receiver so `Substream`s can be handed a sender: a
    /// stream writes by sending commands, the same path every other task
    /// uses. There is exactly one route into the driver, which is why the
    /// ordering guarantees hold.
    commands_tx: mpsc::Sender<Command>,
    commands_rx: mpsc::Receiver<Command>,
    incoming_tx: mpsc::Sender<IncomingStream>,
    writers: Arc<Mutex<Vec<Waker>>>,
    streams: HashMap<u32, Stream>,
    /// Set by `Command::Shutdown`: the loop ends on it, which drops the
    /// socket halves and every stream.
    ended: bool,
}

struct Stream {
    /// Where inbound bytes go. `None` after the peer half-closed: the local
    /// reader then sees EOF, while writes may still flow.
    inbound: Option<mpsc::Sender<Vec<u8>>>,
    /// The local reader, held here only between an outbound `Open` and the
    /// peer's `Opened` — at which point it moves into the `Substream` the
    /// caller is waiting for. Bytes that arrive before `Opened` wait in the
    /// channel rather than being dropped or outrunning the reply.
    reader: Option<mpsc::Receiver<Vec<u8>>>,
    /// The waiting `open`, answered with `Opened` or `Refused`.
    opening: Option<oneshot::Sender<Result<Substream>>>,
}

impl<T, R> Driver<T, R>
where
    T: MessageTx,
    R: MessageRx,
{
    async fn run(mut self) {
        loop {
            let event = tokio::select! {
                command = self.commands_rx.recv() => match command {
                    Some(command) => Event::Command(command),
                    None => Event::Ended,
                },
                message = self.rx.recv_msg() => match message {
                    Ok(Some(message)) => Event::Message(message),
                    // `Ok(None)` is the peer's clean close and `Err` a broken
                    // one; a multiplexer cannot do anything different with
                    // either — every stream ends — so both land on `Ended`.
                    _ => Event::Ended,
                },
            };

            match event {
                Event::Command(command) => self.handle_command(command).await,
                Event::Message(message) => self.handle_message(message).await,
                Event::Ended => break,
            }
            if self.ended {
                break;
            }

            // A command was consumed, so the command queue has room, and a
            // message was consumed, so an inbound channel may have room.
            // Either way, parked writers get another look.
            for waker in self.writers.lock().expect("mux writer lock").drain(..) {
                waker.wake();
            }
        }

        // Dropping `streams` is what ends every stream: each reader channel
        // closes (readers see EOF) and each pending `open` reply is dropped
        // (its `open` reports the session closed).
    }

    async fn handle_command(&mut self, command: Command) {
        match command {
            Command::Open {
                stream,
                target,
                reply,
            } => {
                let (inbound_tx, inbound_rx) = mpsc::channel(STREAM_QUEUE);
                self.streams.insert(
                    stream,
                    Stream {
                        inbound: Some(inbound_tx),
                        reader: Some(inbound_rx),
                        opening: Some(reply),
                    },
                );
                if self
                    .tx
                    .send_msg(&RelayMessage::Open { stream, target })
                    .await
                    .is_err()
                {
                    self.fail_opening(stream, "session closed while opening the stream");
                }
            }

            Command::Answer { stream, result } => match result {
                Ok(()) => {
                    let _ = self.tx.send_msg(&RelayMessage::Opened { stream }).await;
                }
                Err(reason) => {
                    self.streams.remove(&stream);
                    let _ = self
                        .tx
                        .send_msg(&RelayMessage::Refused { stream, reason })
                        .await;
                }
            },

            Command::Data { stream, bytes } => {
                // Unknown stream: it was refused, reset, or finished at both
                // ends before this write drained. Dropping the bytes is the
                // same answer a closed TCP socket gives.
                if !self.streams.contains_key(&stream) {
                    return;
                }
                let _ = self
                    .tx
                    .send_msg(&RelayMessage::Data { stream, bytes })
                    .await;
            }

            Command::Close { stream } => {
                let _ = self.tx.send_msg(&RelayMessage::Close { stream }).await;
            }

            Command::Reset { stream } => {
                self.streams.remove(&stream);
                let _ = self.tx.send_msg(&RelayMessage::Reset { stream }).await;
            }

            Command::Done { stream } => {
                self.streams.remove(&stream);
            }

            Command::Shutdown => {
                // The loop breaks on `Ended`; the driver drops `tx` and `rx`,
                // which is what closes the socket the session rides on.
                self.ended = true;
            }
        }
    }

    async fn handle_message(&mut self, message: RelayMessage) {
        match message {
            RelayMessage::Open { stream, target } => {
                let (inbound_tx, inbound_rx) = mpsc::channel(STREAM_QUEUE);
                self.streams.insert(
                    stream,
                    Stream {
                        inbound: Some(inbound_tx),
                        reader: None,
                        opening: None,
                    },
                );
                let incoming = IncomingStream {
                    target,
                    stream: Some(Substream {
                        id: stream,
                        commands: self.commands_tx.clone(),
                        writers: self.writers.clone(),
                        inbound: inbound_rx,
                        chunk: None,
                        chunk_pos: 0,
                        write_closed: false,
                        reset: false,
                    }),
                    answered: false,
                };
                // Blocks when the accept queue is full: an application that
                // stops accepting stops the session, which is the honest
                // signal and is bounded here rather than growing forever.
                if let Err(mut refused) = self.incoming_tx.send(incoming).await {
                    // Nobody is accepting — the accepting side was dropped.
                    // Answer the peer directly; an `open` must never be left
                    // hanging because this end lost interest. `answered` is
                    // set first so dropping the returned value does not queue
                    // a second, duplicate answer.
                    refused.0.answered = true;
                    drop(refused);
                    self.streams.remove(&stream);
                    let _ = self
                        .tx
                        .send_msg(&RelayMessage::Refused {
                            stream,
                            reason: "this node does not accept streams".to_string(),
                        })
                        .await;
                }
            }

            RelayMessage::Opened { stream } => {
                if let Some(entry) = self.streams.get_mut(&stream) {
                    if let (Some(reply), Some(inbound)) =
                        (entry.opening.take(), entry.reader.take())
                    {
                        let _ = reply.send(Ok(Substream {
                            id: stream,
                            commands: self.commands_tx.clone(),
                            writers: self.writers.clone(),
                            inbound,
                            chunk: None,
                            chunk_pos: 0,
                            write_closed: false,
                            reset: false,
                        }));
                    }
                }
            }

            RelayMessage::Refused { stream, reason } => {
                if let Some(entry) = self.streams.remove(&stream) {
                    if let Some(reply) = entry.opening {
                        let _ = reply.send(Err(Error::custom(reason)));
                    }
                }
            }

            RelayMessage::Data { stream, bytes } => {
                let Some(inbound) = self
                    .streams
                    .get(&stream)
                    .and_then(|entry| entry.inbound.clone())
                else {
                    // Unknown stream, or one whose read direction is already
                    // closed here. Either way there is no reader, and a reset
                    // tells the peer not to wait. Resets for unknown streams
                    // are themselves ignored, so this cannot loop.
                    let _ = self.tx.send_msg(&RelayMessage::Reset { stream }).await;
                    return;
                };
                // Awaited, not tried: this is where a slow local reader
                // becomes backpressure on the session (see the module note).
                if inbound.send(bytes).await.is_err() {
                    // The reader was dropped: the application is done with
                    // this stream. Stop the peer from sending more.
                    self.streams.remove(&stream);
                    let _ = self.tx.send_msg(&RelayMessage::Reset { stream }).await;
                }
            }

            RelayMessage::Close { stream } => {
                if let Some(entry) = self.streams.get_mut(&stream) {
                    // Half-close: the reader sees EOF, the writer continues.
                    entry.inbound = None;
                }
            }

            RelayMessage::Reset { stream } => {
                // Unknown ids are ignored on purpose: a reset crossing a
                // reset must not beget one more.
                self.streams.remove(&stream);
            }
        }
    }

    fn fail_opening(&mut self, stream: u32, reason: &str) {
        if let Some(entry) = self.streams.remove(&stream) {
            if let Some(reply) = entry.opening {
                let _ = reply.send(Err(Error::custom(reason)));
            }
        }
    }
}

// endregion: --- Driver

// region:    --- Substream

/// One conversation over a session, shaped like a byte stream.
pub struct Substream {
    id: u32,
    commands: mpsc::Sender<Command>,
    writers: Arc<Mutex<Vec<Waker>>>,
    inbound: mpsc::Receiver<Vec<u8>>,
    /// The tail of a chunk a short read left behind.
    chunk: Option<Vec<u8>>,
    chunk_pos: usize,
    write_closed: bool,
    reset: bool,
}

impl Substream {
    /// The stream's id. Nothing in the binary reads it — the driver and the
    /// peer are the parties that need it — but the tests pin the parity
    /// contract (initiator odd, responder even) through it, and an id is the
    /// first thing a stream-level log line would want.
    #[cfg(test)]
    pub fn id(&self) -> u32 {
        self.id
    }

    /// Abort: both ends drop the stream now, without the half-close
    /// handshake. What a pump calls when it gives up mid-transfer.
    pub fn reset(&mut self) {
        self.reset = true;
        let _ = self.commands.try_send(Command::Reset { stream: self.id });
    }

    fn park(&self, cx: &Context<'_>) {
        self.writers
            .lock()
            .expect("mux writer lock")
            .push(cx.waker().clone());
    }
}

impl Drop for Substream {
    fn drop(&mut self) {
        if self.reset {
            // `reset` already told the driver and the peer.
            return;
        }
        if !self.write_closed {
            // Dropped without a shutdown and without a reset: the writer half
            // is gone but the transfer never finished at both ends. A close
            // is still the truthful summary — "no more bytes from me" — and
            // it frees the peer's reader rather than leaving it waiting for a
            // shutdown that will never come.
            let _ = self.commands.try_send(Command::Close { stream: self.id });
        }
        // Local bookkeeping can go regardless: this `Substream` was the only
        // reader, and the write path checks for the entry before sending.
        let _ = self.commands.try_send(Command::Done { stream: self.id });
    }
}

impl AsyncRead for Substream {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        let this = self.get_mut();

        // A zero-length read must not consume a chunk: returning zero filled
        // bytes would read as EOF to the caller.
        if buf.remaining() == 0 {
            return Poll::Ready(Ok(()));
        }

        // Serve the tail of a chunk a short read left behind first.
        if let Some(chunk) = this.chunk.take() {
            let remaining = &chunk[this.chunk_pos..];
            let n = remaining.len().min(buf.remaining());
            buf.put_slice(&remaining[..n]);
            this.chunk_pos += n;
            if this.chunk_pos < chunk.len() {
                this.chunk = Some(chunk);
            } else {
                this.chunk_pos = 0;
            }
            return Poll::Ready(Ok(()));
        }

        match this.inbound.poll_recv(cx) {
            Poll::Ready(Some(chunk)) => {
                let n = chunk.len().min(buf.remaining());
                buf.put_slice(&chunk[..n]);
                if n < chunk.len() {
                    this.chunk_pos = n;
                    this.chunk = Some(chunk);
                }
                Poll::Ready(Ok(()))
            }
            // The driver dropped the sender: a clean half-close, an abort,
            // or the whole session ending. All three are EOF to a reader.
            Poll::Ready(None) => Poll::Ready(Ok(())),
            Poll::Pending => Poll::Pending,
        }
    }
}

impl AsyncWrite for Substream {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        let this = self.get_mut();
        if this.write_closed {
            return Poll::Ready(Err(std::io::Error::new(
                std::io::ErrorKind::BrokenPipe,
                "stream half-closed by this side",
            )));
        }
        match this.commands.try_send(Command::Data {
            stream: this.id,
            bytes: buf.to_vec(),
        }) {
            Ok(()) => Poll::Ready(Ok(buf.len())),
            Err(mpsc::error::TrySendError::Full(_)) => {
                this.park(cx);
                Poll::Pending
            }
            Err(mpsc::error::TrySendError::Closed(_)) => {
                // The driver is gone: the session ended. Report the write as
                // broken rather than parking on a channel nothing reads.
                Poll::Ready(Err(std::io::Error::new(
                    std::io::ErrorKind::BrokenPipe,
                    "session closed",
                )))
            }
        }
    }

    fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        // Ordering is the driver's channel; nothing is buffered here.
        Poll::Ready(Ok(()))
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        let this = self.get_mut();
        if this.write_closed {
            return Poll::Ready(Ok(()));
        }
        match this.commands.try_send(Command::Close { stream: this.id }) {
            Ok(()) => {
                this.write_closed = true;
                Poll::Ready(Ok(()))
            }
            Err(mpsc::error::TrySendError::Full(_)) => {
                this.park(cx);
                Poll::Pending
            }
            Err(mpsc::error::TrySendError::Closed(_)) => {
                // Session already gone; closing is moot but not an error.
                this.write_closed = true;
                Poll::Ready(Ok(()))
            }
        }
    }
}

// endregion: --- Substream

// region:    --- Incoming stream

/// A stream the peer opened, awaiting this side's answer.
///
/// The answer is where authorization lives: the peer's `open` is waiting on
/// it, and the refusal it carries is the only thing the dialing side learns.
pub struct IncomingStream {
    target: String,
    /// `Option` only so `accept` can move it out of a type that has a `Drop`
    /// impl; it is `Some` from construction until one of the two answers.
    stream: Option<Substream>,
    answered: bool,
}

impl IncomingStream {
    /// What the peer asked to reach.
    pub fn target(&self) -> &str {
        &self.target
    }

    /// Accept: the peer may start sending, and gets `Opened`.
    pub fn accept(mut self) -> (String, Substream) {
        self.answered = true;
        let _ = self.stream().commands.try_send(Command::Answer {
            stream: self.stream().id,
            result: Ok(()),
        });
        let stream = self
            .stream
            .take()
            .expect("stream is present until it is answered");
        (self.target.clone(), stream)
    }

    /// Refuse: the peer's `open` returns this reason.
    pub fn refuse(mut self, reason: &str) {
        self.answered = true;
        let _ = self.stream().commands.try_send(Command::Answer {
            stream: self.stream().id,
            result: Err(reason.to_string()),
        });
    }

    fn stream(&self) -> &Substream {
        self.stream
            .as_ref()
            .expect("stream is present until it is answered")
    }
}

impl Drop for IncomingStream {
    fn drop(&mut self) {
        if !self.answered {
            // Dropped without an answer. The peer's `open` must not hang on
            // this side's bookkeeping, so the drop itself becomes a refusal.
            if let Some(stream) = self.stream.as_ref() {
                let _ = stream.commands.try_send(Command::Answer {
                    stream: stream.id,
                    result: Err("the accepting side dropped the stream".to_string()),
                });
            }
        }
    }
}

// endregion: --- Incoming stream

// region:    --- Tests

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    /// Sessions over in-memory channels. Real sessions cost two post-quantum
    /// handshakes per test, and nothing here is about the crypto: this module
    /// is the bookkeeping.
    struct ChanTx(mpsc::UnboundedSender<RelayMessage>);
    struct ChanRx {
        msgs: mpsc::UnboundedReceiver<RelayMessage>,
        /// The session's off switch: firing it makes this half report the
        /// session closed, which is the only way a test can end a session —
        /// each driver holds its own send half, so nothing else ever closes
        /// a channel.
        abort: Arc<tokio::sync::Notify>,
    }

    impl MessageTx for ChanTx {
        async fn send_msg(&mut self, message: &RelayMessage) -> Result<()> {
            self.0
                .send(message.clone())
                .map_err(|_| Error::custom("test channel closed"))
        }
    }

    impl MessageRx for ChanRx {
        async fn recv_msg(&mut self) -> Result<Option<RelayMessage>> {
            tokio::select! {
                message = self.msgs.recv() => Ok(message),
                _ = self.abort.notified() => Ok(None),
            }
        }
    }

    /// Two session endpoints, wired to each other, with each side's off
    /// switch handed back. `a` initiated (odd ids).
    #[allow(clippy::type_complexity)]
    fn breakable_pair() -> (
        (MuxSession, Arc<tokio::sync::Notify>),
        (MuxSession, Arc<tokio::sync::Notify>),
    ) {
        let (a_tx, a_rx) = mpsc::unbounded_channel();
        let (b_tx, b_rx) = mpsc::unbounded_channel();
        let a_abort = Arc::new(tokio::sync::Notify::new());
        let b_abort = Arc::new(tokio::sync::Notify::new());
        // Crossed: what A sends is what B receives. A's own `msgs` receiver
        // must be fed by B's sender, or A hears only its own echo.
        (
            (
                MuxSession::initiator(
                    ChanTx(a_tx),
                    ChanRx {
                        msgs: b_rx,
                        abort: a_abort.clone(),
                    },
                ),
                a_abort,
            ),
            (
                MuxSession::responder(
                    ChanTx(b_tx),
                    ChanRx {
                        msgs: a_rx,
                        abort: b_abort.clone(),
                    },
                ),
                b_abort,
            ),
        )
    }

    /// Two session endpoints that stay up for the whole test.
    fn pair() -> (MuxSession, MuxSession) {
        let ((a, _a_off), (b, _b_off)) = breakable_pair();
        (a, b)
    }

    #[tokio::test]
    async fn a_stream_carries_bytes_both_ways() {
        let (a, mut b) = pair();
        let a_mux = a.handle();

        let server = tokio::spawn(async move {
            let incoming = b.accept().await.expect("inbound stream");
            assert_eq!(incoming.target(), "svc");
            let (_target, mut stream) = incoming.accept();

            let mut buf = vec![0u8; 1024];
            let n = stream.read(&mut buf).await.unwrap();
            assert_eq!(&buf[..n], b"ping");
            stream.write_all(b"pong").await.unwrap();
            stream.shutdown().await.unwrap();
        });

        let mut stream = a_mux.open("svc").await.expect("open");
        stream.write_all(b"ping").await.unwrap();
        stream.shutdown().await.unwrap();

        let mut echoed = Vec::new();
        stream.read_to_end(&mut echoed).await.unwrap();
        assert_eq!(echoed, b"pong");

        server.await.unwrap();
    }

    #[tokio::test]
    async fn refusal_reaches_the_dialer() {
        let (a, mut b) = pair();
        let a_mux = a.handle();

        let server = tokio::spawn(async move {
            let incoming = b.accept().await.expect("inbound stream");
            assert_eq!(incoming.target(), "evil:22");
            incoming.refuse("evil:22 is not granted to this client");
        });

        let err = a_mux
            .open("evil:22")
            .await
            .err()
            .expect("refusal must reach the dialer")
            .to_string();
        assert!(err.contains("not granted"), "error was: {}", err);

        server.await.unwrap();
        // The session survives a refusal: it is a per-stream answer, not a
        // connection-level event.
        assert!(!a_mux.is_closed());
    }

    #[tokio::test]
    async fn streams_are_independent() {
        let (a, mut b) = pair();
        let a_mux = a.handle();

        let server = tokio::spawn(async move {
            for _ in 0..2 {
                let incoming = b.accept().await.expect("inbound stream");
                let (target, mut stream) = incoming.accept();
                tokio::spawn(async move {
                    let mut buf = vec![0u8; 64];
                    let n = stream.read(&mut buf).await.unwrap();
                    // Echo the target name back so the client can prove which
                    // conversation it got.
                    let reply = format!("{}:{}", target, String::from_utf8_lossy(&buf[..n]));
                    stream.write_all(reply.as_bytes()).await.unwrap();
                    stream.shutdown().await.unwrap();
                });
            }
        });

        // Interleaved on purpose: open both, then write to them in an order
        // that differs from the open order.
        let mut first = a_mux.open("one").await.unwrap();
        let mut second = a_mux.open("two").await.unwrap();
        // Distinct ids, and the parity contract between the two sides.
        assert_ne!(first.id(), second.id());
        assert_eq!(first.id() % 2, 1);
        assert_eq!(second.id() % 2, 1);

        second.write_all(b"B").await.unwrap();
        first.write_all(b"A").await.unwrap();
        first.shutdown().await.unwrap();
        second.shutdown().await.unwrap();

        let mut from_first = String::new();
        first.read_to_string(&mut from_first).await.unwrap();
        let mut from_second = String::new();
        second.read_to_string(&mut from_second).await.unwrap();

        assert_eq!(from_first, "one:A");
        assert_eq!(from_second, "two:B");

        server.await.unwrap();
    }

    #[tokio::test]
    async fn both_sides_can_open() {
        let (mut a, mut b) = pair();
        let a_mux = a.handle();
        let b_mux = b.handle();

        // The initiator opens toward B…
        let from_b = tokio::spawn(async move {
            let incoming = b.accept().await.expect("inbound stream");
            let (target, mut stream) = incoming.accept();
            stream.write_all(target.as_bytes()).await.unwrap();
            stream.shutdown().await.unwrap();
        });

        let mut stream = a_mux.open("to-b").await.unwrap();
        let mut reply = String::new();
        stream.read_to_string(&mut reply).await.unwrap();
        assert_eq!(reply, "to-b");
        from_b.await.unwrap();

        // …and B opens toward A over the same session, with even ids.
        let from_a = tokio::spawn(async move {
            let incoming = a.accept().await.expect("inbound stream");
            let (target, mut stream) = incoming.accept();
            stream.write_all(target.as_bytes()).await.unwrap();
            stream.shutdown().await.unwrap();
        });

        let mut stream = b_mux.open("to-a").await.unwrap();
        assert_eq!(stream.id() % 2, 0, "responder side must use even ids");
        let mut reply = String::new();
        stream.read_to_string(&mut reply).await.unwrap();
        assert_eq!(reply, "to-a");
        from_a.await.unwrap();
    }

    /// The half-close is directional: after the client shuts its write half
    /// the server can still answer — the shape `nc -N` and HTTP/1.0 produce.
    #[tokio::test]
    async fn half_close_keeps_the_other_direction_open() {
        let (a, mut b) = pair();
        let a_mux = a.handle();

        let server = tokio::spawn(async move {
            let incoming = b.accept().await.expect("inbound stream");
            let (_target, mut stream) = incoming.accept();

            // Read to EOF — the client's half-close — and *then* answer.
            let mut request = Vec::new();
            stream.read_to_end(&mut request).await.unwrap();
            assert_eq!(request, b"request");
            stream.write_all(b"response").await.unwrap();
            stream.shutdown().await.unwrap();
        });

        let mut stream = a_mux.open("svc").await.unwrap();
        stream.write_all(b"request").await.unwrap();
        stream.shutdown().await.unwrap();

        let mut response = Vec::new();
        stream.read_to_end(&mut response).await.unwrap();
        assert_eq!(response, b"response");

        server.await.unwrap();
    }

    /// A stream dropped without an answer refuses the peer rather than
    /// hanging its `open`, and the session keeps working afterwards.
    #[tokio::test]
    async fn an_unanswered_stream_is_refused_not_hung() {
        let (a, mut b) = pair();
        let a_mux = a.handle();

        let churn = tokio::spawn(async move {
            let incoming = b.accept().await.expect("inbound stream");
            drop(incoming); // no answer

            let incoming = b.accept().await.expect("second inbound stream");
            let (_target, mut stream) = incoming.accept();
            stream.write_all(b"alive").await.unwrap();
            stream.shutdown().await.unwrap();
        });

        let err = a_mux
            .open("dropped")
            .await
            .err()
            .expect("no answer must surface as a refusal")
            .to_string();
        assert!(err.contains("dropped the stream"), "error was: {}", err);

        let mut stream = a_mux.open("second").await.unwrap();
        let mut reply = Vec::new();
        stream.read_to_end(&mut reply).await.unwrap();
        assert_eq!(reply, b"alive");

        churn.await.unwrap();
    }

    /// A reset stream must not disturb its neighbours on the session.
    #[tokio::test]
    async fn a_reset_stream_does_not_disturb_its_neighbours() {
        let (a, mut b) = pair();
        let a_mux = a.handle();

        let server = tokio::spawn(async move {
            let incoming = b.accept().await.expect("inbound stream");
            let (_target, mut stream) = incoming.accept();
            stream.reset();

            let incoming = b.accept().await.expect("second inbound stream");
            let (_target, mut stream) = incoming.accept();
            stream.write_all(b"unharmed").await.unwrap();
            stream.shutdown().await.unwrap();
        });

        let mut aborted = a_mux.open("doomed").await.expect("open");
        aborted.reset();

        let mut stream = a_mux.open("healthy").await.unwrap();
        let mut reply = Vec::new();
        stream.read_to_end(&mut reply).await.unwrap();
        assert_eq!(reply, b"unharmed");

        server.await.unwrap();
    }

    /// Data larger than a single chunk, through a stream, intact — the
    /// chunk-splitting path in `poll_read` and the backpressure path in the
    /// driver both have to hold for this to pass.
    #[tokio::test]
    async fn a_large_transfer_is_byte_exact() {
        let (a, mut b) = pair();
        let a_mux = a.handle();

        const SIZE: usize = 512 * 1024;
        let expected: Vec<u8> = (0..SIZE).map(|i| (i % 251) as u8).collect();

        let server = tokio::spawn(async move {
            let incoming = b.accept().await.expect("inbound stream");
            let (_target, mut stream) = incoming.accept();
            let mut received = Vec::new();
            stream.read_to_end(&mut received).await.unwrap();
            stream.write_all(&received).await.unwrap();
            stream.shutdown().await.unwrap();
        });

        let mut stream = a_mux.open("bulk").await.unwrap();
        let payload = expected.clone();
        let writer = tokio::spawn(async move {
            stream.write_all(&payload).await.unwrap();
            stream.shutdown().await.unwrap();
            let mut echoed = Vec::new();
            stream.read_to_end(&mut echoed).await.unwrap();
            echoed
        });

        let echoed = writer.await.unwrap();
        assert_eq!(echoed.len(), expected.len());
        assert!(echoed == expected, "payload changed in transit");

        server.await.unwrap();
    }

    /// The operator's kick: `shutdown` from any handle ends the whole
    /// session exactly like the peer hanging up — every stream ends, the
    /// accept loop sees the session gone, and a second shutdown is a no-op.
    #[tokio::test]
    async fn shutdown_ends_every_stream_like_a_session_end() {
        let (a, mut b) = pair();
        let a_mux = a.handle();

        let server = tokio::spawn(async move {
            let incoming = b.accept().await.expect("inbound stream");
            let (_target, mut stream) = incoming.accept();
            let mut buf = [0u8; 16];
            // The kick arrives while this stream is mid-conversation: the
            // reader sees EOF, not a hang.
            assert_eq!(
                stream.read(&mut buf).await.unwrap(),
                0,
                "kicked stream must see EOF"
            );
            // The accept loop then ends too — the session is gone.
            assert!(b.accept().await.is_none(), "kicked session accepts nothing");
        });

        let mut stream = a_mux.open("doomed").await.expect("open");
        a_mux.shutdown();

        // Everything after the kick behaves like a session that ended. The
        // waits below are what prove it: each one parks until the driver has
        // actually processed the kick and dropped the session.
        let err = a_mux
            .open("after")
            .await
            .err()
            .expect("a kicked session opens nothing")
            .to_string();
        assert!(err.contains("session closed"), "error was: {}", err);
        assert!(a_mux.is_closed());
        assert_eq!(
            stream.read(&mut [0u8; 16]).await.unwrap(),
            0,
            "the kicker's own streams see EOF"
        );

        a_mux.shutdown(); // a second kick is a no-op, not a panic
        server.await.unwrap();
    }

    /// When the session ends, every stream ends: readers see EOF, a pending
    /// `open` reports the session gone, and later opens fail immediately —
    /// nothing waits forever on a session that no longer exists.
    #[tokio::test]
    async fn session_end_ends_every_stream() {
        let ((a, _a_off), (mut b, b_off)) = breakable_pair();
        let a_mux = a.handle();

        // One stream established…
        let established = tokio::spawn({
            let a_mux = a_mux.clone();
            async move { a_mux.open("established").await }
        });
        let incoming = b.accept().await.expect("inbound stream");
        let (_, _server_stream) = incoming.accept();
        let mut stream = established.await.unwrap().unwrap();

        // …and one open in flight, which stays unanswered: the responder
        // never accepts it, so its `open` is still waiting when the session
        // dies.
        let opening = tokio::spawn({
            let a_mux = a_mux.clone();
            async move { a_mux.open("in-flight").await }
        });

        // Now the session dies under all three.
        b_off.notify_one();

        let mut buf = [0u8; 16];
        assert_eq!(
            stream.read(&mut buf).await.unwrap(),
            0,
            "an established stream's reader must see EOF"
        );

        let refused = opening
            .await
            .unwrap()
            .err()
            .expect("an in-flight open cannot outlive its session")
            .to_string();
        assert!(refused.contains("session closed"), "error was: {}", refused);

        let err = a_mux
            .open("after")
            .await
            .err()
            .expect("a dead session opens nothing")
            .to_string();
        assert!(err.contains("session closed"), "error was: {}", err);
        assert!(a_mux.is_closed());

        drop(a);
    }
}

// endregion: --- Tests
