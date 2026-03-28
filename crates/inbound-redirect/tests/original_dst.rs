#![cfg(target_os = "linux")]

use tokio::net::{TcpListener, TcpStream};
use veex_inbound_redirect::{resolve_original_dst, RedirectError};

#[tokio::test]
async fn original_dst_requires_a_redirected_socket() {
    let listener = TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, 0))
        .await
        .expect("listener should bind");
    let addr = listener.local_addr().expect("listener addr should exist");

    let accept_task = tokio::spawn(async move {
        let (stream, _) = listener.accept().await.expect("accept should succeed");
        resolve_original_dst(&stream)
    });

    let _client = TcpStream::connect(addr)
        .await
        .expect("client should connect");
    let result = accept_task.await.expect("accept task should join");

    match result {
        Err(RedirectError::GetSockOpt { .. }) | Err(RedirectError::UnsupportedAddressFamily(_)) => {
        }
        Err(other) => panic!("unexpected original dst error: {other}"),
        Ok(destination) => panic!("expected original dst resolution to fail, got {destination}"),
    }
}
