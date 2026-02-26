//! Transport-agnostic request dispatch.
//!
//! This module exposes a small API for feeding raw FUSE request bytes into fuser's
//! existing parser and `Filesystem` dispatch path without requiring `/dev/fuse`.

use std::convert::TryFrom;
use std::io;
use std::sync::Arc;

use nix::unistd::geteuid;

use crate::ll;
use crate::ll::Request as _;
use crate::request::{DispatchOutcome as RequestDispatchOutcome, DispatchState};
use crate::Filesystem;
use crate::ReplySender;
use crate::Request;
use crate::SessionACL;

/// Access-control inputs used by [`handle_request`].
#[derive(Debug, Clone, Copy)]
pub struct DispatchContext {
    /// UID filtering mode (same behavior as session ACL checks).
    pub acl: SessionACL,
    /// UID that owns the serving process.
    pub session_owner_uid: u32,
}

impl DispatchContext {
    /// Create a new context with explicit ACL and owner uid.
    pub fn new(acl: SessionACL, session_owner_uid: u32) -> Self {
        Self {
            acl,
            session_owner_uid,
        }
    }
}

impl Default for DispatchContext {
    fn default() -> Self {
        Self {
            acl: SessionACL::Owner,
            session_owner_uid: geteuid().as_raw(),
        }
    }
}

/// Result of processing one init request with [`handle_init`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct InitOutcome {
    /// Kernel ABI version from the incoming init request.
    pub kernel_abi: ll::Version,
    /// Whether initialization completed.
    pub completed: bool,
}

/// High-level result of dispatching one non-init request.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DispatchOutcome {
    /// Continue serving further requests.
    Continue,
    /// A destroy request was handled.
    Destroy,
}

impl From<RequestDispatchOutcome> for DispatchOutcome {
    fn from(value: RequestDispatchOutcome) -> Self {
        match value {
            RequestDispatchOutcome::Continue => DispatchOutcome::Continue,
            RequestDispatchOutcome::Destroy => DispatchOutcome::Destroy,
        }
    }
}

/// Handle a single `FUSE_INIT` request.
///
/// The caller should invoke this before dispatching regular requests.
pub fn handle_init<FS: Filesystem>(
    filesystem: &mut FS,
    request_bytes: &[u8],
    sender: Arc<dyn ReplySender>,
) -> io::Result<InitOutcome> {
    let parsed = parse_request(request_bytes)?;
    let init = match parsed
        .operation()
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "failed to parse init operation"))?
    {
        ll::Operation::Init(init) => init,
        _ => {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "expected FUSE_INIT request",
            ));
        }
    };

    let request = Request::new_with_sender(sender, request_bytes).ok_or_else(|| {
        io::Error::new(io::ErrorKind::InvalidData, "failed to parse init request")
    })?;

    let mut state = DispatchState {
        allowed: SessionACL::Owner,
        session_owner: geteuid().as_raw(),
        proto_major: 0,
        proto_minor: 0,
        initialized: false,
        destroyed: false,
    };

    match request.dispatch_with_state(filesystem, &mut state) {
        Ok(_) => Ok(InitOutcome {
            kernel_abi: init.version(),
            completed: state.initialized,
        }),
        Err(errno) => Err(io::Error::from_raw_os_error(errno.into())),
    }
}

/// Handle a single non-init request.
///
/// All reply bytes are emitted via `sender`. For requests that return no reply
/// (`forget`, `batch_forget`), this function only invokes filesystem callbacks.
pub fn handle_request<FS: Filesystem>(
    filesystem: &mut FS,
    request_bytes: &[u8],
    sender: Arc<dyn ReplySender>,
    context: &DispatchContext,
) -> io::Result<DispatchOutcome> {
    let parsed = parse_request(request_bytes)?;
    if matches!(
        parsed.operation().map_err(request_parse_error)?,
        ll::Operation::Init(_)
    ) {
        // `handle_request` is only for post-init messages.
        let response = parsed.reply_err(ll::Errno::EIO);
        response
            .with_iovec(parsed.unique(), |iov| sender.send(iov))
            .map_err(|err| io::Error::new(io::ErrorKind::BrokenPipe, err.to_string()))?;
        return Ok(DispatchOutcome::Continue);
    }

    let request = Request::new_with_sender(sender, request_bytes)
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "failed to parse request"))?;
    let mut state = DispatchState {
        allowed: context.acl,
        session_owner: context.session_owner_uid,
        // `handle_request` is for post-init operations only.
        initialized: true,
        destroyed: false,
        proto_major: 0,
        proto_minor: 0,
    };
    Ok(request
        .dispatch_with_state(filesystem, &mut state)
        .map_err(|errno| io::Error::from_raw_os_error(errno.into()))?
        .into())
}

fn parse_request<'a>(request_bytes: &'a [u8]) -> io::Result<ll::AnyRequest<'a>> {
    ll::AnyRequest::try_from(request_bytes).map_err(request_parse_error)
}

fn request_parse_error(err: ll::RequestError) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, err.to_string())
}
