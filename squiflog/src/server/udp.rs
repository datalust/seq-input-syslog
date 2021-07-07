use std::net::SocketAddr;

use crate::{diagnostics::*, error::Error};

use bytes::{Bytes, BytesMut};

use futures::{Stream, StreamExt};

use tokio::net::UdpSocket;

use tokio_util::{codec::Decoder, udp::UdpFramed};

pub(super) struct Server(UdpSocket);

impl Server {
    pub(super) async fn bind(addr: &SocketAddr) -> Result<Self, Error> {
        let sock = UdpSocket::bind(&addr).await?;

        Ok(Server(sock))
    }

    pub(super) fn build(self) -> impl Stream<Item = Result<Bytes, Error>> {
        emit("Setting up for UDP");

        UdpFramed::new(self.0, Decode).map(|r| r.map(|(msg, _)| msg)) // ignore socket, just take message
    }
}

struct Decode;

impl Decoder for Decode {
    type Item = Bytes;
    type Error = Error;

    fn decode(&mut self, src: &mut BytesMut) -> Result<Option<Self::Item>, Self::Error> {
        // All datagrams are considered a valid message
        // Split the Bytes mut into two components, and freeze the first one (initialised part, into a Bytes non-mut)
        let src = src.split_to(src.len()).freeze();

        if src.is_empty() {
            return Ok(None);
        }

        Ok(Some(src))
    }
}
