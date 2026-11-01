use std::time::Duration;

pub fn socks_client(port: u16, connect_timeout: Duration) -> anyhow::Result<reqwest::Client> {
    let proxy = reqwest::Proxy::all(format!("socks5h://127.0.0.1:{port}"))?;
    let client = reqwest::Client::builder()
        .proxy(proxy)
        .connect_timeout(connect_timeout)
        .http1_only()
        .build()?;
    Ok(client)
}

#[cfg(test)]
mod tests {
    use super::socks_client;
    use std::time::Duration;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    #[tokio::test]
    async fn socks_client_sends_domain_name_to_the_proxy_for_remote_resolution() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let proxy = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();

            let mut greeting = [0; 2];
            stream.read_exact(&mut greeting).await.unwrap();
            let mut methods = vec![0; greeting[1] as usize];
            stream.read_exact(&mut methods).await.unwrap();
            assert_eq!(greeting[0], 5);
            assert!(methods.contains(&0));
            stream.write_all(&[5, 0]).await.unwrap();

            let mut request = [0; 4];
            stream.read_exact(&mut request).await.unwrap();
            assert_eq!(request, [5, 1, 0, 3], "proxy should receive a domain name");
            let mut length = [0; 1];
            stream.read_exact(&mut length).await.unwrap();
            let mut domain = vec![0; length[0] as usize];
            stream.read_exact(&mut domain).await.unwrap();
            let mut remote_port = [0; 2];
            stream.read_exact(&mut remote_port).await.unwrap();

            (
                String::from_utf8(domain).unwrap(),
                u16::from_be_bytes(remote_port),
            )
        });

        let client = socks_client(port, Duration::from_secs(2)).unwrap();
        let result = client
            .get("http://must-be-resolved-by-proxy.invalid:8080/")
            .send()
            .await;
        assert!(
            result.is_err(),
            "fixture intentionally does not establish a tunnel"
        );
        assert_eq!(
            proxy.await.unwrap(),
            ("must-be-resolved-by-proxy.invalid".to_owned(), 8080)
        );
    }
}
