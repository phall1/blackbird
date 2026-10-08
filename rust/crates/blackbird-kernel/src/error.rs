//! Failures an agent can branch on. A refused claim is not one of these:
//! [`crate::ClaimResult`] carries `ok: false` and the holders.

/// A coordination call that did not change the requested fact.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// The bearer token is missing, unknown, or not the token for that name.
    #[error("{0}")]
    Unauthenticated(String),
    /// The call cannot work as sent. Change it before retrying.
    #[error("{0}")]
    Invalid(String),
    /// The named agent, message, or claim is not visible here.
    #[error("{0}")]
    NotFound(String),
    /// A `name@host` recipient needs the Go daemon's peer mail.
    #[error(
        "this kernel has no cross-host mail, so a name@host recipient cannot be delivered; send to agents on this host only"
    )]
    RemoteUnsupported,
    /// Tracker, spend, and contention-cost observations are not in this kernel.
    #[error("{0}")]
    DependencyUnavailable(String),
    /// SQLite could not complete the call.
    #[error("{0}")]
    Storage(String),
}

impl Error {
    pub(crate) fn unauthenticated(message: impl Into<String>) -> Self {
        Self::Unauthenticated(message.into())
    }

    pub(crate) fn invalid(message: impl Into<String>) -> Self {
        Self::Invalid(message.into())
    }

    pub(crate) fn not_found(message: impl Into<String>) -> Self {
        Self::NotFound(message.into())
    }

    /// Stable machine code. Branch on this, not on the sentence.
    #[must_use]
    pub fn code(&self) -> &'static str {
        match self {
            Self::Unauthenticated(_) => "UNAUTHENTICATED",
            Self::Invalid(_) => "INVALID",
            Self::NotFound(_) => "NOT_FOUND",
            Self::RemoteUnsupported => "REMOTE_UNSUPPORTED",
            Self::DependencyUnavailable(_) => "DEPENDENCY_UNAVAILABLE",
            Self::Storage(_) => "INTERNAL",
        }
    }

    /// Family the code belongs to.
    #[must_use]
    pub fn category(&self) -> &'static str {
        match self {
            Self::Unauthenticated(_) => "authentication",
            Self::Invalid(_) | Self::NotFound(_) | Self::RemoteUnsupported => "validation",
            Self::DependencyUnavailable(_) => "dependency",
            Self::Storage(_) => "internal",
        }
    }

    /// Repeating the same call can succeed later only for a storage failure.
    #[must_use]
    pub fn retryable(&self) -> bool {
        matches!(self, Self::Storage(_))
    }
}
