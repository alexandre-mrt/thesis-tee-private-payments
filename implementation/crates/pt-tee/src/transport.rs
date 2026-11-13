//! TCP and vsock listeners and connectors behind one [`Endpoint`] type.
//!
//! The enclave listens on vsock (Nitro) or TCP loopback (`--mock`); `pt-host`
//! listens on TCP and connects to vsock; clients connect to TCP. All of them
//! only need a boxed byte stream, so accept/connect return a [`Stream`].
//! vsock is compiled only on Linux; elsewhere vsock endpoints fail with
//! [`TransportError::VsockUnsupported`].

use std::fmt;
use std::str::FromStr;

use tokio::io::{AsyncRead, AsyncWrite};
use tokio::net::{TcpListener, TcpStream};

/// `VMADDR_CID_ANY`: bind a vsock listener on every CID (what the enclave does).
pub const VSOCK_CID_ANY: u32 = u32::MAX;

const VSOCK_SCHEME: &str = "vsock://";
const TCP_SCHEME: &str = "tcp://";

/// Transport errors.
#[derive(Debug, thiserror::Error)]
pub enum TransportError {
    /// The endpoint string could not be parsed.
    #[error("invalid endpoint {input:?}: {reason}")]
    InvalidEndpoint { input: String, reason: String },
    /// vsock requested on a platform without vsock support.
    #[error("vsock endpoints are only supported on Linux guests")]
    VsockUnsupported,
    /// Socket I/O failure.
    #[error("i/o error on {endpoint}: {source}")]
    Io {
        endpoint: Endpoint,
        #[source]
        source: std::io::Error,
    },
}

/// A listen or connect target.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Endpoint {
    /// `host:port`, resolved by tokio at connect/bind time.
    Tcp(String),
    /// vsock context id and port.
    Vsock { cid: u32, port: u32 },
}

impl fmt::Display for Endpoint {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Endpoint::Tcp(addr) => write!(f, "{TCP_SCHEME}{addr}"),
            Endpoint::Vsock { cid, port } => write!(f, "{VSOCK_SCHEME}{cid}:{port}"),
        }
    }
}

impl FromStr for Endpoint {
    type Err = TransportError;

    /// Accepts `vsock://CID:PORT`, `tcp://HOST:PORT` or a bare `HOST:PORT`.
    fn from_str(input: &str) -> Result<Self, Self::Err> {
        let invalid = |reason: &str| TransportError::InvalidEndpoint {
            input: input.to_owned(),
            reason: reason.to_owned(),
        };
        if let Some(rest) = input.strip_prefix(VSOCK_SCHEME) {
            let (cid, port) = rest
                .split_once(':')
                .ok_or_else(|| invalid("expected vsock://CID:PORT"))?;
            let cid = cid
                .parse::<u32>()
                .map_err(|_| invalid("CID is not a u32"))?;
            let port = port
                .parse::<u32>()
                .map_err(|_| invalid("port is not a u32"))?;
            return Ok(Endpoint::Vsock { cid, port });
        }
        let addr = input.strip_prefix(TCP_SCHEME).unwrap_or(input);
        let (host, port) = addr
            .rsplit_once(':')
            .ok_or_else(|| invalid("expected HOST:PORT"))?;
        if host.is_empty() {
            return Err(invalid("empty host"));
        }
        port.parse::<u16>()
            .map_err(|_| invalid("port is not a u16"))?;
        Ok(Endpoint::Tcp(addr.to_owned()))
    }
}

impl Endpoint {
    /// TCP endpoint from a `host:port` string (validated).
    pub fn tcp(addr: &str) -> Result<Self, TransportError> {
        let parsed: Endpoint = addr.parse()?;
        match parsed {
            Endpoint::Tcp(_) => Ok(parsed),
            Endpoint::Vsock { .. } => Err(TransportError::InvalidEndpoint {
                input: addr.to_owned(),
                reason: "expected a TCP address".to_owned(),
            }),
        }
    }

    /// vsock endpoint.
    pub fn vsock(cid: u32, port: u32) -> Self {
        Endpoint::Vsock { cid, port }
    }

    /// True for a TCP endpoint whose host is a loopback address (`127.0.0.0/8`,
    /// `::1` or the literal `localhost`). Mock attestation is only acceptable
    /// on such endpoints: anything else is a network peer that must attest.
    pub fn is_loopback(&self) -> bool {
        let Endpoint::Tcp(addr) = self else {
            return false;
        };
        let Some((host, _port)) = addr.rsplit_once(':') else {
            return false;
        };
        let host = host.trim_start_matches('[').trim_end_matches(']');
        host.eq_ignore_ascii_case("localhost")
            || host
                .parse::<std::net::IpAddr>()
                .is_ok_and(|ip| ip.is_loopback())
    }

    fn io(&self, source: std::io::Error) -> TransportError {
        TransportError::Io {
            endpoint: self.clone(),
            source,
        }
    }
}

/// Anything we can read from and write to asynchronously.
pub trait Duplex: AsyncRead + AsyncWrite + Unpin + Send {}
impl<T: AsyncRead + AsyncWrite + Unpin + Send> Duplex for T {}

/// A connected byte stream (TCP or vsock).
pub type Stream = Box<dyn Duplex>;

/// A bound listener.
pub enum Listener {
    Tcp(TcpListener),
    #[cfg(target_os = "linux")]
    Vsock(tokio_vsock::VsockListener),
}

impl Listener {
    /// Binds on `endpoint`. For vsock, use [`VSOCK_CID_ANY`] as CID.
    pub async fn bind(endpoint: &Endpoint) -> Result<Self, TransportError> {
        match endpoint {
            Endpoint::Tcp(addr) => TcpListener::bind(addr)
                .await
                .map(Listener::Tcp)
                .map_err(|e| endpoint.io(e)),
            #[cfg(target_os = "linux")]
            Endpoint::Vsock { cid, port } => {
                tokio_vsock::VsockListener::bind(tokio_vsock::VsockAddr::new(*cid, *port))
                    .map(Listener::Vsock)
                    .map_err(|e| endpoint.io(e))
            }
            #[cfg(not(target_os = "linux"))]
            Endpoint::Vsock { .. } => Err(TransportError::VsockUnsupported),
        }
    }

    /// Accepts one connection and returns it with the peer endpoint.
    pub async fn accept(&self) -> Result<(Stream, Endpoint), TransportError> {
        match self {
            Listener::Tcp(l) => {
                let (stream, peer) = l.accept().await.map_err(|e| self.io(e))?;
                Ok((Box::new(stream), Endpoint::Tcp(peer.to_string())))
            }
            #[cfg(target_os = "linux")]
            Listener::Vsock(l) => {
                let (stream, peer) = l.accept().await.map_err(|e| self.io(e))?;
                Ok((Box::new(stream), Endpoint::vsock(peer.cid(), peer.port())))
            }
        }
    }

    /// The endpoint actually bound (useful after binding port 0).
    pub fn local_endpoint(&self) -> Result<Endpoint, TransportError> {
        match self {
            Listener::Tcp(l) => l
                .local_addr()
                .map(|a| Endpoint::Tcp(a.to_string()))
                .map_err(|e| self.io(e)),
            #[cfg(target_os = "linux")]
            Listener::Vsock(l) => l
                .local_addr()
                .map(|a| Endpoint::vsock(a.cid(), a.port()))
                .map_err(|e| self.io(e)),
        }
    }

    fn io(&self, source: std::io::Error) -> TransportError {
        let endpoint = match self {
            Listener::Tcp(l) => l
                .local_addr()
                .map(|a| Endpoint::Tcp(a.to_string()))
                .unwrap_or_else(|_| Endpoint::Tcp("unknown".to_owned())),
            #[cfg(target_os = "linux")]
            Listener::Vsock(l) => l
                .local_addr()
                .map(|a| Endpoint::vsock(a.cid(), a.port()))
                .unwrap_or_else(|_| Endpoint::vsock(VSOCK_CID_ANY, 0)),
        };
        TransportError::Io { endpoint, source }
    }
}

/// Connects to `endpoint`.
pub async fn connect(endpoint: &Endpoint) -> Result<Stream, TransportError> {
    match endpoint {
        Endpoint::Tcp(addr) => {
            let stream = TcpStream::connect(addr).await.map_err(|e| endpoint.io(e))?;
            stream.set_nodelay(true).map_err(|e| endpoint.io(e))?;
            Ok(Box::new(stream))
        }
        #[cfg(target_os = "linux")]
        Endpoint::Vsock { cid, port } => {
            let stream =
                tokio_vsock::VsockStream::connect(tokio_vsock::VsockAddr::new(*cid, *port))
                    .await
                    .map_err(|e| endpoint.io(e))?;
            Ok(Box::new(stream))
        }
        #[cfg(not(target_os = "linux"))]
        Endpoint::Vsock { .. } => Err(TransportError::VsockUnsupported),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::framing::{read_cbor, write_cbor};

    #[test]
    fn loopback_detection() {
        for addr in [
            "127.0.0.1:8443",
            "127.5.6.7:1",
            "localhost:5005",
            "LOCALHOST:1",
            "[::1]:8443",
        ] {
            assert!(Endpoint::tcp(addr).unwrap().is_loopback(), "{addr}");
        }
        for addr in [
            "10.0.0.1:8443",
            "0.0.0.0:8443",
            "example.com:8443",
            "[fe80::1]:1",
        ] {
            assert!(!Endpoint::tcp(addr).unwrap().is_loopback(), "{addr}");
        }
        assert!(!Endpoint::vsock(16, 5005).is_loopback());
    }

    #[test]
    fn endpoint_parsing() {
        assert_eq!(
            "vsock://16:5005".parse::<Endpoint>().unwrap(),
            Endpoint::vsock(16, 5005)
        );
        assert_eq!(
            "tcp://127.0.0.1:8443".parse::<Endpoint>().unwrap(),
            Endpoint::Tcp("127.0.0.1:8443".to_owned())
        );
        assert_eq!(
            "example.com:8443".parse::<Endpoint>().unwrap(),
            Endpoint::Tcp("example.com:8443".to_owned())
        );
        assert_eq!(
            "[::1]:5005".parse::<Endpoint>().unwrap(),
            Endpoint::Tcp("[::1]:5005".to_owned())
        );
        for bad in [
            "",
            "nohost",
            ":5005",
            "host:99999",
            "vsock://16",
            "vsock://x:1",
        ] {
            assert!(
                matches!(
                    bad.parse::<Endpoint>(),
                    Err(TransportError::InvalidEndpoint { .. })
                ),
                "{bad}"
            );
        }
        assert!(Endpoint::tcp("vsock://1:2").is_err());
        assert_eq!(Endpoint::vsock(16, 5005).to_string(), "vsock://16:5005");
        assert_eq!(
            Endpoint::Tcp("0.0.0.0:8443".to_owned()).to_string(),
            "tcp://0.0.0.0:8443"
        );
    }

    #[test]
    fn vsock_cid_any_matches_libc() {
        assert_eq!(VSOCK_CID_ANY, 0xFFFF_FFFF);
        #[cfg(target_os = "linux")]
        assert_eq!(VSOCK_CID_ANY, tokio_vsock::VMADDR_CID_ANY);
    }

    #[tokio::test]
    async fn tcp_listen_connect_and_exchange_frames() {
        let listener = Listener::bind(&Endpoint::tcp("127.0.0.1:0").unwrap())
            .await
            .unwrap();
        let endpoint = listener.local_endpoint().unwrap();
        assert!(matches!(&endpoint, Endpoint::Tcp(a) if a.starts_with("127.0.0.1:")));

        let server = tokio::spawn(async move {
            let (mut stream, peer) = listener.accept().await.unwrap();
            assert!(matches!(peer, Endpoint::Tcp(_)));
            let msg: Vec<u8> = read_cbor(&mut stream).await.unwrap();
            let reply: Vec<u8> = msg.iter().rev().copied().collect();
            write_cbor(&mut stream, &reply).await.unwrap();
        });

        let mut client = connect(&endpoint).await.unwrap();
        write_cbor(&mut client, &vec![1u8, 2, 3]).await.unwrap();
        let reply: Vec<u8> = read_cbor(&mut client).await.unwrap();
        assert_eq!(reply, vec![3, 2, 1]);
        server.await.unwrap();
    }

    #[tokio::test]
    async fn connect_refused_is_an_io_error() {
        let listener = Listener::bind(&Endpoint::tcp("127.0.0.1:0").unwrap())
            .await
            .unwrap();
        let endpoint = listener.local_endpoint().unwrap();
        drop(listener);
        let err = connect(&endpoint)
            .await
            .err()
            .expect("connection must fail");
        assert!(matches!(err, TransportError::Io { .. }), "{err}");
    }

    #[cfg(not(target_os = "linux"))]
    #[tokio::test]
    async fn vsock_is_unsupported_off_linux() {
        let ep = Endpoint::vsock(16, 5005);
        assert!(matches!(
            Listener::bind(&ep).await.err(),
            Some(TransportError::VsockUnsupported)
        ));
        assert!(matches!(
            connect(&ep).await.err(),
            Some(TransportError::VsockUnsupported)
        ));
    }
}
