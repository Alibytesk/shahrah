use std::io;
use std::pin::Pin;
use std::task::{Context, Poll};

use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::net::TcpStream;
use tokio_rustls::{client::TlsStream as ClientTls, server::TlsStream as ServerTls};

pub enum Transport {
    Placeholder,
    Plain(TcpStream),
    ServerTls(Box<ServerTls<TcpStream>>),
    ClientTls(Box<ClientTls<TcpStream>>),
}

impl Transport {

}

impl AsyncRead for Transport {
    fn poll_read(
        self: Pin<&mut Self>,
        context: &mut Context<'_>,
        buffer: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        match self.get_mut() {
            Self::Placeholder => Poll::Ready(Ok(())),
            Self::Plain(stream) => Pin::new(stream).poll_read(context, buffer),
            Self::ServerTls(stream) => Pin::new(stream.as_mut()).poll_read(context, buffer),
            Self::ClientTls(stream) => Pin::new(stream.as_mut()).poll_read(context, buffer),
        }
    }
}

impl AsyncWrite for Transport {
    fn poll_write(
        self: Pin<&mut Self>,
        context: &mut Context<'_>,
        buffer: &[u8],
    ) -> Poll<io::Result<usize>> {
        match self.get_mut() {
            Self::Placeholder => Poll::Ready(Ok(0)),
            Self::Plain(stream) => Pin::new(stream).poll_write(context, buffer),
            Self::ServerTls(stream) => Pin::new(stream.as_mut()).poll_write(context, buffer),
            Self::ClientTls(stream) => Pin::new(stream.as_mut()).poll_write(context, buffer),
        }
    }

    fn poll_flush(self: Pin<&mut Self>, context: &mut Context<'_>) -> Poll<io::Result<()>> {
        match self.get_mut() {
            Self::Placeholder => Poll::Ready(Ok(())),
            Self::Plain(stream) => Pin::new(stream).poll_flush(context),
            Self::ServerTls(stream) => Pin::new(stream.as_mut()).poll_flush(context),
            Self::ClientTls(stream) => Pin::new(stream.as_mut()).poll_flush(context),
        }
    }

    fn poll_shutdown(self: Pin<&mut Self>, context: &mut Context<'_>) -> Poll<io::Result<()>> {
        match self.get_mut() {
            Self::Placeholder => Poll::Ready(Ok(())),
            Self::Plain(stream) => Pin::new(stream).poll_shutdown(context),
            Self::ServerTls(stream) => Pin::new(stream.as_mut()).poll_shutdown(context),
            Self::ClientTls(stream) => Pin::new(stream.as_mut()).poll_shutdown(context),
        }
    }
}
