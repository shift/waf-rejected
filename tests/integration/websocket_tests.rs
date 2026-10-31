//! End-to-end WebSocket upgrade/tunnel test.

use std::sync::Arc;

use futures_util::{SinkExt, StreamExt};
use tokio::net::TcpListener;
use tokio_tungstenite::tungstenite::Message;

use waf_ingress::proxy::WafProxyService;
use waf_ingress::Config;

async fn spawn_ws_upstream() -> std::net::SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();

    tokio::spawn(async move {
        let (stream, _) = listener.accept().await.unwrap();
        let mut ws = tokio_tungstenite::accept_async(stream).await.unwrap();
        while let Some(Ok(message)) = ws.next().await {
            if message.is_text() {
                if ws.send(message).await.is_err() {
                    break;
                }
            }
        }
    });

    addr
}

async fn spawn_proxy(upstream: std::net::SocketAddr) -> String {
    let mut config = Config::default();
    config.upstream_uri = format!("http://{}", upstream);
    config.server.max_body_size = 4096;
    config.waf.rate_limit.per_ip_enabled = false;
    config.waf.rate_limit.global_enabled = false;

    let service = Arc::new(WafProxyService::new(config).unwrap());
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        let _ = service.start_with_listener(listener).await;
    });

    format!("{}", addr)
}

#[tokio::test]
async fn websocket_upgrade_is_tunneled_to_upstream() {
    let upstream = spawn_ws_upstream().await;
    let proxy = spawn_proxy(upstream).await;

    let (mut client, _) = tokio_tungstenite::connect_async(format!("ws://{}/ws", proxy))
        .await
        .expect("websocket handshake through proxy");

    client
        .send(Message::Text("hello-through-waf".into()))
        .await
        .unwrap();

    let echoed = tokio::time::timeout(std::time::Duration::from_secs(3), client.next())
        .await
        .expect("echo timeout")
        .expect("stream closed")
        .expect("websocket error");

    assert_eq!(echoed, Message::Text("hello-through-waf".into()));
}
