//! Plain TCP serving: one enclave instance per connection.
//!
//! Each connection gets a fresh enclave (and therefore a fresh identity
//! key), exactly like a process per connection under `stunnel`. The TLS
//! layer of the remote executor is transport only (`docs/PROTOCOL.md` §5),
//! so plain TCP offers the same security; use it for local tests, compose
//! setups, or behind a TLS terminator of your choice.

use std::io;
use std::net::{TcpListener, TcpStream};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::Duration;

use crate::log::info;
use crate::serve::{SessionSummary, attest, serve_session};
use crate::{EnclaveBackend, HostError, Quoter};

/// Limits for [`serve_tcp`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TcpOptions {
    /// Concurrent sessions (enclave instances). Further connections are
    /// closed immediately.
    pub max_sessions: usize,
    /// A session ends when the client sends nothing for this long.
    pub idle_timeout: Option<Duration>,
}

impl Default for TcpOptions {
    fn default() -> Self {
        Self {
            max_sessions: 8,
            idle_timeout: Some(Duration::from_secs(300)),
        }
    }
}

/// Accepts connections forever. `make_enclave` creates the enclave of each
/// session; the quoter is shared (and serialized) between sessions.
pub fn serve_tcp<F, E, Q>(
    listener: TcpListener,
    options: TcpOptions,
    make_enclave: F,
    quoter: Q,
) -> io::Result<()>
where
    F: Fn() -> Result<E, HostError> + Send + Sync + 'static,
    E: EnclaveBackend,
    Q: Quoter + Send + 'static,
{
    let make_enclave = Arc::new(make_enclave);
    let quoter = Arc::new(Mutex::new(quoter));
    let active = Arc::new(AtomicUsize::new(0));
    let mut next_id: u64 = 0;
    info!("listening on {}", listener.local_addr()?);
    for stream in listener.incoming() {
        let stream = match stream {
            Ok(s) => s,
            Err(e) => {
                // E.g. EMFILE: back off instead of spinning.
                info!("accept failed: {e}");
                thread::sleep(Duration::from_millis(100));
                continue;
            }
        };
        next_id += 1;
        let id = next_id;
        let peer = stream
            .peer_addr()
            .map_or_else(|_| "?".to_owned(), |a| a.to_string());
        if active.fetch_add(1, Ordering::AcqRel) >= options.max_sessions {
            active.fetch_sub(1, Ordering::AcqRel);
            info!(
                "session {id} from {peer}: refused, {} sessions active",
                options.max_sessions
            );
            continue;
        }
        let (session_make, session_quoter, session_active) =
            (make_enclave.clone(), quoter.clone(), active.clone());
        let spawned = thread::Builder::new()
            .name(format!("session-{id}"))
            .spawn(move || {
                info!("session {id} from {peer}: started");
                match serve_connection(
                    &stream,
                    options.idle_timeout,
                    &*session_make,
                    &session_quoter,
                ) {
                    Ok(s) => info!(
                        "session {id}: closed by client after {} requests ({} failed)",
                        s.requests, s.failures
                    ),
                    Err(e) => info!("session {id}: ended: {e}"),
                }
                session_active.fetch_sub(1, Ordering::AcqRel);
            });
        if let Err(e) = spawned {
            info!("session {id}: cannot spawn a thread: {e}");
            active.fetch_sub(1, Ordering::AcqRel);
        }
    }
    Ok(())
}

/// Runs one session on an accepted connection: new enclave, attestation
/// (holding the quoter lock), then the request loop.
pub fn serve_connection<F, E, Q>(
    stream: &TcpStream,
    idle_timeout: Option<Duration>,
    make_enclave: &F,
    quoter: &Mutex<Q>,
) -> Result<SessionSummary, HostError>
where
    F: Fn() -> Result<E, HostError> + ?Sized,
    E: EnclaveBackend,
    Q: Quoter,
{
    stream.set_read_timeout(idle_timeout)?;
    stream.set_nodelay(true)?;
    let mut enclave = make_enclave()?;
    let quote = {
        let mut quoter = quoter
            .lock()
            .map_err(|_| HostError::Config("quoter lock poisoned".into()))?;
        attest(&mut enclave, &mut *quoter)?
    };
    serve_session(&mut enclave, &quote, stream, stream)
}

#[cfg(test)]
mod tests {
    use std::io::{Read, Write};
    use std::net::Shutdown;

    use sgx_ra_core::wire::Response;

    use super::*;
    use crate::serve::tests::{MockEnclave, MockQuoter, parse_output};

    #[test]
    fn sessions_get_their_own_enclave() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        thread::spawn(move || {
            serve_tcp(
                listener,
                TcpOptions::default(),
                || Ok(MockEnclave::default()),
                MockQuoter,
            )
        });
        for msg in [&b"first"[..], b"second"] {
            let mut conn = TcpStream::connect(addr).unwrap();
            let mut frame = (msg.len() as u32).to_be_bytes().to_vec();
            frame.extend_from_slice(msg);
            conn.write_all(&frame).unwrap();
            conn.shutdown(Shutdown::Write).unwrap();
            let mut out = Vec::new();
            conn.read_to_end(&mut out).unwrap();
            let (quote, responses) = parse_output(&out);
            assert!(quote.starts_with(b"QUOTE"));
            assert_eq!(responses, vec![Response::Ok(msg.to_vec())]);
        }
    }

    #[test]
    fn idle_sessions_time_out() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let _client = TcpStream::connect(addr).unwrap();
        let (server, _) = listener.accept().unwrap();
        let quoter = Mutex::new(MockQuoter);
        let err = serve_connection(
            &server,
            Some(Duration::from_millis(50)),
            &|| Ok(MockEnclave::default()),
            &quoter,
        )
        .unwrap_err();
        assert!(matches!(
            err,
            HostError::Io(e) if matches!(e.kind(), io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut)
        ));
    }
}
