use std::{future::Future, pin::Pin};

use veex_core::{
    Result,
    io::{BoxedAsyncStream, PacketSessionHandle},
    types::Destination,
};

pub type StreamAdapterFuture<'a> =
    Pin<Box<dyn Future<Output = Result<BoxedAsyncStream>> + Send + 'a>>;
pub type PacketAdapterFuture<'a> =
    Pin<Box<dyn Future<Output = Result<PacketSessionHandle>> + Send + 'a>>;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct StreamParams {
    pub destination: Destination,
    pub buffered_payload: Vec<u8>,
}

impl StreamParams {
    pub fn new(destination: Destination, buffered_payload: Vec<u8>) -> Self {
        Self {
            destination,
            buffered_payload,
        }
    }
}

pub trait StreamAdapter: Send + Sync {
    fn establish<'a>(
        &'a self,
        stream: BoxedAsyncStream,
        params: StreamParams,
    ) -> StreamAdapterFuture<'a>;
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PacketParams {
    pub destination: Destination,
    pub buffered_payload: Vec<u8>,
}

impl PacketParams {
    pub fn new(destination: Destination, buffered_payload: Vec<u8>) -> Self {
        Self {
            destination,
            buffered_payload,
        }
    }
}

pub trait PacketAdapter: Send + Sync {
    fn establish<'a>(
        &'a self,
        session: PacketSessionHandle,
        params: PacketParams,
    ) -> PacketAdapterFuture<'a>;
}
