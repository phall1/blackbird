//! Coordination kernel for Blackbird.
//!
//! Eight operations — join, claim, release, status, say, read, ack, and wait —
//! sit behind [`Desk`]. The kernel keeps one SQLite file, hashes bearer tokens,
//! and does not open a phux socket or the Go daemon's database. A `name@host`
//! recipient is refused rather than dropped.

#![forbid(unsafe_code)]

mod desk;
mod error;
mod model;
mod time;

pub use desk::Desk;
pub use error::Error;
pub use model::{
    AckOut, AgentOut, ClaimResult, ConversationSummary, DeliveryOut, HeldReservation, HolderOut,
    InboxItem, InboxSummary, JoinOut, MessageOut, PageOut, PeerOut, ProjectReport, ReservationOut,
    SayOut, SayRequest, Selector, SelectorOut, StatusOut, Summary, WaitOut, WaitReason,
};
