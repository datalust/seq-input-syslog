use std::{marker::Unpin, str::FromStr};

use futures::{future::BoxFuture, select, FutureExt, StreamExt};

use tokio::{runtime::Runtime, signal::ctrl_c, sync::oneshot};

use bytes::Bytes;

use crate::diagnostics::*;
use crate::error::Error;

mod udp;

metrics! {
    receive_ok,
    receive_err,
    process_ok,
    process_err
}

/**
Server configuration.
*/
#[derive(Debug, Clone)]
pub struct Config {
    /**
    The address to bind the server to.
    */
    pub bind: Bind,
}

#[derive(Debug, Clone)]
pub struct Bind {
    pub addr: String,
    pub protocol: Protocol,
}

#[derive(Debug, Clone, Copy)]
pub enum Protocol {
    Udp,
}

impl FromStr for Bind {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.get(0..6) {
            Some("udp://") => Ok(Bind {
                addr: s[6..].to_owned(),
                protocol: Protocol::Udp,
            }),
            _ => Ok(Bind {
                addr: s.to_owned(),
                protocol: Protocol::Udp,
            }),
        }
    }
}

impl Default for Config {
    fn default() -> Self {
        Config {
            bind: Bind {
                addr: "0.0.0.0:514".to_owned(),
                protocol: Protocol::Udp,
            },
        }
    }
}

/**
A SYSLOG server.
*/
pub struct Server {
    fut: BoxFuture<'static, ()>,
    handle: Option<Handle>,
}

impl Server {
    pub fn take_handle(&mut self) -> Option<Handle> {
        self.handle.take()
    }

    pub fn run(self) -> Result<(), Error> {
        // Run the server on a fresh runtime
        // We attempt to shut this runtime down cleanly to release
        // any used resources
        let mut runtime = Runtime::new().expect("failed to start new Runtime");

        runtime.block_on(self.fut);

        Ok(())
    }
}

/**
A handle to a running SYSLOG server that can be used to interact with it
programmatically.
*/
pub struct Handle {
    close: oneshot::Sender<()>,
}

impl Handle {
    /**
    Close the server.
    */
    pub fn close(self) -> bool {
        self.close.send(()).is_ok()
    }
}

pub fn build(
    config: Config,
    mut process: impl FnMut(Bytes) -> Result<(), Error> + Send + Sync + Unpin + Clone + 'static,
) -> Result<Server, Error> {
    emit("Starting SYSLOG server");

    let addr = config.bind.addr.parse()?;
    let (handle_tx, handle_rx) = oneshot::channel();

    // Build a handle
    let handle = Some(Handle { close: handle_tx });

    let server = async move {
        let incoming = udp::Server::bind(&addr).await?.build();

        let mut close = handle_rx.fuse();
        let mut ctrl_c = ctrl_c().boxed().fuse();
        let mut incoming = incoming.fuse();

        // NOTE: We don't use `?` here because we never want to carry results
        // We always want to match them and deal with error cases directly
        loop {
            select! {
                // A message that's ready to process
                msg = incoming.next() => match msg {
                    // A complete message has been received
                    Some(Ok(msg)) => {
                        increment!(server.receive_ok);

                        // Process the received message
                        match process(msg) {
                            Ok(()) => {
                                increment!(server.process_ok);
                            }
                            Err(err) => {
                                increment!(server.process_err);
                                emit_err(&err, "SYSLOG processing failed");
                            }
                        }
                    },
                    // An error occurred receiving a chunk
                    Some(Err(err)) => {
                        increment!(server.receive_err);
                        emit_err(&err, "SYSLOG processing failed");
                    },
                    None => {
                        unreachable!("receiver stream should never terminate")
                    },
                },
                // A termination signal from the programmatic handle
                _ = close => {
                    emit("Handle closed; shutting down");
                    break;
                },
                // A termination signal from the environment
                _ = ctrl_c => {
                    emit("Termination signal received; shutting down");
                    break;
                },
            };
        }

        emit("Stopping SYSLOG server");

        Result::Ok::<(), Error>(())
    };

    Ok(Server {
        fut: Box::pin(async move {
            if let Err(err) = server.await {
                emit_err(&err, "SYSLOG server failed");
            }
        }),
        handle,
    })
}
