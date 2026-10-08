//! Replaced by the transport slice. The process binds the listener first.
use blackbird_kernel::Desk;
use std::io;
use std::net::TcpListener;

pub fn serve(_desk: &Desk, _listener: TcpListener) -> io::Result<()> {
    Err(io::Error::new(
        io::ErrorKind::Unsupported,
        "HTTP adapter is linked by the transport slice",
    ))
}
