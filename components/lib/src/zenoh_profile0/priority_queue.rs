//! A bounded queue of publications, one ring for each priority.
//!
//! The queue belongs to the owner of a link, which sizes it and lends it to `Link::drain`. It holds `DEPTH`
//! publications of each of the 8 priorities, a key of up to `KEY` bytes and a payload of up to `PAYLOAD` bytes in each.
//! The next publication is the oldest one of the lowest priority number that holds any. A publication takes its
//! sequence number when it leaves the queue, so a discarded one leaves no gap on its lane.

use super::MAX_ATTACHMENT_BYTES;
use super::Qos;
use super::encode::EncodeError;
use super::lane::PRIORITIES;
use crate::zenoh_link::Published;

const PRIORITY_COUNT: usize = PRIORITIES as usize;

/// Why [`PriorityQueue::push`] refuses a publication.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PushError {
    /// The ring of the publication's priority is full and the publication blocks.
    QueueFull,
    /// The key, the attachment or the payload is one the queue cannot hold.
    Encode(EncodeError),
}

impl From<EncodeError> for PushError {
    fn from(error: EncodeError) -> Self {
        Self::Encode(error)
    }
}

/// One queued publication, copied in so the caller's buffers are free after the push.
#[derive(Clone, Copy)]
pub(crate) struct Entry<const KEY: usize, const PAYLOAD: usize> {
    key: [u8; KEY],
    key_len: usize,
    attachment: [u8; MAX_ATTACHMENT_BYTES],
    payload: [u8; PAYLOAD],
    payload_len: usize,
    qos: Qos,
}

impl<const KEY: usize, const PAYLOAD: usize> Entry<KEY, PAYLOAD> {
    pub(crate) fn key(&self) -> &str {
        self.key
            .get(..self.key_len)
            .and_then(|bytes| core::str::from_utf8(bytes).ok())
            .unwrap_or("")
    }

    pub(crate) fn attachment(&self) -> &[u8] {
        &self.attachment
    }

    pub(crate) fn payload(&self) -> &[u8] {
        self.payload.get(..self.payload_len).unwrap_or(&[])
    }

    pub(crate) const fn qos(&self) -> Qos {
        self.qos
    }
}

/// `DEPTH` publications for each priority, whose keys and payloads are bounded by `KEY` and `PAYLOAD`.
pub struct PriorityQueue<const DEPTH: usize, const KEY: usize, const PAYLOAD: usize> {
    entries: [[Option<Entry<KEY, PAYLOAD>>; DEPTH]; PRIORITY_COUNT],
    head: [usize; PRIORITY_COUNT],
    held: [usize; PRIORITY_COUNT],
    dropped: u32,
}

impl<const DEPTH: usize, const KEY: usize, const PAYLOAD: usize> Default
    for PriorityQueue<DEPTH, KEY, PAYLOAD>
{
    fn default() -> Self {
        Self::new()
    }
}

impl<const DEPTH: usize, const KEY: usize, const PAYLOAD: usize>
    PriorityQueue<DEPTH, KEY, PAYLOAD>
{
    pub const fn new() -> Self {
        Self {
            entries: [[None; DEPTH]; PRIORITY_COUNT],
            head: [0; PRIORITY_COUNT],
            held: [0; PRIORITY_COUNT],
            dropped: 0,
        }
    }

    /// Queues a publication on the ring of its priority. A full ring discards a Drop publication and counts it, and
    /// refuses a Block one as [`PushError::QueueFull`]. A key, attachment or payload the queue cannot hold is refused as
    /// the encoder refuses it, and changes nothing. A ring that is full does not stop another priority.
    pub fn push(
        &mut self,
        key: &str,
        attachment: &[u8],
        payload: &[u8],
        qos: Qos,
    ) -> Result<Published, PushError> {
        if key.len() > KEY {
            return Err(EncodeError::KeyTooLong.into());
        }
        if attachment.len() != MAX_ATTACHMENT_BYTES {
            return Err(EncodeError::AttachmentLength.into());
        }
        if payload.len() > PAYLOAD {
            return Err(EncodeError::PayloadTooLong.into());
        }
        let priority = usize::from(qos.priority());
        if self.held[priority] >= DEPTH {
            if qos.block() {
                return Err(PushError::QueueFull);
            }
            self.dropped = self.dropped.saturating_add(1);
            return Ok(Published::Dropped);
        }
        let mut entry = Entry {
            key: [0; KEY],
            key_len: key.len(),
            attachment: [0; MAX_ATTACHMENT_BYTES],
            payload: [0; PAYLOAD],
            payload_len: payload.len(),
            qos,
        };
        entry.key[..key.len()].copy_from_slice(key.as_bytes());
        entry.attachment.copy_from_slice(attachment);
        entry.payload[..payload.len()].copy_from_slice(payload);
        let at = (self.head[priority] + self.held[priority]) % DEPTH;
        self.entries[priority][at] = Some(entry);
        self.held[priority] += 1;
        Ok(Published::Queued)
    }

    /// The priority and the publication that leave next: the oldest of the lowest priority number that holds any.
    pub(crate) fn next(&self) -> Option<(usize, &Entry<KEY, PAYLOAD>)> {
        let priority = self.held.iter().position(|held| *held > 0)?;
        let entry = self.entries[priority][self.head[priority]].as_ref()?;
        Some((priority, entry))
    }

    /// Takes the publication [`next`](Self::next) named off the ring of `priority`.
    pub(crate) fn discard(&mut self, priority: usize) {
        if self.held[priority] == 0 {
            return;
        }
        self.entries[priority][self.head[priority]] = None;
        self.head[priority] = (self.head[priority] + 1) % DEPTH;
        self.held[priority] -= 1;
    }

    /// How many publications the queue holds.
    pub fn len(&self) -> usize {
        self.held.iter().sum()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// How many Drop publications a full ring discarded. It saturates.
    pub const fn dropped(&self) -> u32 {
        self.dropped
    }
}
