use std::future::Future;
use std::io;
use std::pin::Pin;
use std::task::{Context, Poll};

use native_tls::{Error as NativeTlsError, TlsConnector as NativeTlsConnector};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio_native_tls::{TlsConnector as TokioTlsConnector, TlsStream as TokioNativeTlsStream};
use tokio_postgres::tls::{ChannelBinding, MakeTlsConnect, TlsConnect, TlsStream};

#[derive(Clone)]
pub struct PostgresNativeTlsConnector {
    connector: NativeTlsConnector,
}

impl PostgresNativeTlsConnector {
    pub fn new(connector: NativeTlsConnector) -> Self {
        Self { connector }
    }
}

pub struct PostgresTlsConnect {
    connector: TokioTlsConnector,
    domain: String,
}

pub struct PostgresTlsStream<S>(TokioNativeTlsStream<S>);

impl<S> MakeTlsConnect<S> for PostgresNativeTlsConnector
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    type Stream = PostgresTlsStream<S>;
    type TlsConnect = PostgresTlsConnect;
    type Error = NativeTlsError;

    fn make_tls_connect(&mut self, domain: &str) -> Result<Self::TlsConnect, Self::Error> {
        Ok(PostgresTlsConnect {
            connector: TokioTlsConnector::from(self.connector.clone()),
            domain: domain.to_string(),
        })
    }
}

impl<S> TlsConnect<S> for PostgresTlsConnect
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    type Stream = PostgresTlsStream<S>;
    type Error = NativeTlsError;
    type Future = Pin<Box<dyn Future<Output = Result<Self::Stream, Self::Error>> + Send>>;

    fn connect(self, stream: S) -> Self::Future {
        Box::pin(async move {
            let tls_stream = self.connector.connect(&self.domain, stream).await?;
            Ok(PostgresTlsStream(tls_stream))
        })
    }
}

impl<S> AsyncRead for PostgresTlsStream<S>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        Pin::new(&mut self.0).poll_read(cx, buf)
    }
}

impl<S> AsyncWrite for PostgresTlsStream<S>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.0).poll_write(cx, buf)
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.0).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.0).poll_shutdown(cx)
    }
}

impl<S> TlsStream for PostgresTlsStream<S>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    fn channel_binding(&self) -> ChannelBinding {
        ChannelBinding::none()
    }
}
