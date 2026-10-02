//! Shared, test-only HTTP/3 peer with an optional VLESS header exchange.
use boring::ssl::{SslContextBuilder, SslMethod};
use quiche::h3::NameValue;
use std::{net::SocketAddr, time::Duration};
use tokio::net::UdpSocket;
pub type Captured = Vec<(Vec<u8>, Vec<u8>)>;
pub struct Peer {
    pub addr: SocketAddr,
    pub root: Vec<u8>,
    pub task: tokio::task::JoinHandle<Vec<Captured>>,
}
pub async fn peer(
    bind: &str,
    split: bool,
    status: u16,
    upload_status: u16,
    deferred: bool,
    vless: bool,
) -> Peer {
    let cert = rcgen::generate_simple_self_signed(vec!["example.org".into()]).unwrap();
    let root = cert.cert.der().to_vec();
    let mut ssl = SslContextBuilder::new(SslMethod::tls()).unwrap();
    ssl.set_certificate(&boring::x509::X509::from_der(&root).unwrap())
        .unwrap();
    ssl.set_private_key(
        &boring::pkey::PKey::private_key_from_der(&cert.key_pair.serialize_der()).unwrap(),
    )
    .unwrap();
    let mut config =
        quiche::Config::with_boring_ssl_ctx_builder(quiche::PROTOCOL_VERSION, ssl).unwrap();
    config.set_application_protos(&[b"h3"]).unwrap();
    config.set_initial_max_data(512 * 1024);
    config.set_initial_max_stream_data_bidi_remote(256 * 1024);
    config.set_initial_max_stream_data_uni(16 * 1024);
    config.set_initial_max_streams_bidi(2);
    config.set_initial_max_streams_uni(3);
    config.set_max_idle_timeout(30_000);
    let socket = UdpSocket::bind(bind).await.unwrap();
    let addr = socket.local_addr().unwrap();
    let task = tokio::spawn(async move {
        let mut input = [0u8; 65535];
        let (n, remote) = socket.recv_from(&mut input).await.unwrap();
        let header = quiche::Header::from_slice(&mut input[..n], quiche::MAX_CONN_ID_LEN).unwrap();
        let scid = quiche::ConnectionId::from_ref(&[42; quiche::MAX_CONN_ID_LEN]);
        let mut conn =
            quiche::accept(&scid, Some(&header.dcid), addr, remote, &mut config).unwrap();
        conn.recv(
            &mut input[..n],
            quiche::RecvInfo {
                from: remote,
                to: addr,
            },
        )
        .unwrap();
        let mut http = None;
        let mut captures = Vec::new();
        let mut download = None;
        let mut upload = None;
        let mut sent_headers = false;
        let mut eof = false;
        let mut ack_sent = !split || upload_status != 204;
        let mut fin_sent = false;
        let mut pending = Vec::new();
        let mut request = Vec::new();
        let mut request_done = !vless;
        let mut pending_pos = 0;
        let mut output = [0u8; 1500];
        loop {
            if conn.is_established() && http.is_none() {
                let mut cfg = quiche::h3::Config::new().unwrap();
                cfg.set_max_field_section_size(16 * 1024);
                http = Some(quiche::h3::Connection::with_transport(&mut conn, &cfg).unwrap());
            }
            if let Some(h3) = http.as_mut() {
                loop {
                    match h3.poll(&mut conn) {
                        Ok((id, quiche::h3::Event::Headers { list, .. })) => {
                            let method = list
                                .iter()
                                .find(|h| h.name() == b":method")
                                .unwrap()
                                .value();
                            if method == b"GET" {
                                download = Some(id);
                            } else {
                                upload = Some(id);
                                if !split {
                                    download = Some(id);
                                }
                            }
                            captures.push(
                                list.iter()
                                    .map(|h| (h.name().to_vec(), h.value().to_vec()))
                                    .collect(),
                            );
                            if split && method == b"POST" && upload_status != 204 {
                                h3.send_response(
                                    &mut conn,
                                    id,
                                    &[quiche::h3::Header::new(
                                        b":status",
                                        upload_status.to_string().as_bytes(),
                                    )],
                                    true,
                                )
                                .unwrap();
                            }
                        }
                        Ok((id, quiche::h3::Event::Data)) => {
                            assert_eq!(Some(id), upload);
                            let mut chunk = [0u8; 16 * 1024];
                            loop {
                                match h3.recv_body(&mut conn, id, &mut chunk) {
                                    Ok(n) => {
                                        if request_done {
                                            pending.extend_from_slice(&chunk[..n]);
                                        } else {
                                            request.extend_from_slice(&chunk[..n]);
                                            if request.len() >= 22 {
                                                let offset = 18 + usize::from(request[17]);
                                                if request.len() >= offset + 8 {
                                                    assert_eq!(request[0], 0);
                                                    assert_eq!(
                                                        &request[1..17],
                                                        &[
                                                            0xb8, 0x31, 0x38, 0x1d, 0x63, 0x24,
                                                            0x4d, 0x53, 0xad, 0x4f, 0x8c, 0xda,
                                                            0x48, 0xb3, 0x08, 0x11
                                                        ]
                                                    );
                                                    assert_eq!(request[offset], 1); // TCP
                                                    assert_eq!(request[offset + 3], 1); // IPv4
                                                    let end = offset + 8;
                                                    pending.extend_from_slice(&[0, 0]);
                                                    pending.extend_from_slice(&request[end..]);
                                                    request_done = true;
                                                    request.clear();
                                                }
                                            }
                                        }
                                    }
                                    Err(quiche::h3::Error::Done) => break,
                                    Err(e) => panic!("server body: {e:?}"),
                                }
                            }
                        }
                        Ok((id, quiche::h3::Event::Finished)) if Some(id) == upload => {
                            eof = true;
                        }
                        Ok(_) => {}
                        Err(quiche::h3::Error::Done) => break,
                        Err(e) => panic!("server poll: {e:?}"),
                    }
                }
                if eof && !ack_sent {
                    match h3.send_response(
                        &mut conn,
                        upload.unwrap(),
                        &[quiche::h3::Header::new(b":status", b"204")],
                        true,
                    ) {
                        Ok(()) => ack_sent = true,
                        Err(quiche::h3::Error::StreamBlocked) => {}
                        Err(e) => panic!("upload ack: {e:?}"),
                    }
                }
                if let Some(id) = download {
                    if !sent_headers && (!deferred || !pending.is_empty()) {
                        h3.send_response(
                            &mut conn,
                            id,
                            &[quiche::h3::Header::new(
                                b":status",
                                status.to_string().as_bytes(),
                            )],
                            false,
                        )
                        .unwrap();
                        sent_headers = true;
                    }
                    if sent_headers && pending_pos < pending.len() {
                        match h3.send_body(&mut conn, id, &pending[pending_pos..], false) {
                            Ok(n) => pending_pos += n,
                            Err(quiche::h3::Error::Done)
                            | Err(quiche::h3::Error::StreamBlocked) => {}
                            Err(e) => panic!("server send: {e:?}"),
                        }
                    }
                }
            }
            let done = eof && pending_pos == pending.len() && sent_headers;
            if done && !fin_sent {
                match http
                    .as_mut()
                    .unwrap()
                    .send_body(&mut conn, download.unwrap(), &[], true)
                {
                    Ok(_) => fin_sent = true,
                    Err(quiche::h3::Error::Done) | Err(quiche::h3::Error::StreamBlocked) => {}
                    Err(e) => panic!("download fin: {e:?}"),
                }
            }
            loop {
                match conn.send(&mut output) {
                    Ok((n, info)) => {
                        socket.send_to(&output[..n], info.to).await.unwrap();
                    }
                    Err(quiche::Error::Done) => break,
                    Err(e) => panic!("server QUIC: {e:?}"),
                }
            }
            let wait = conn.timeout().unwrap_or(Duration::from_secs(5));
            tokio::select! {
                result = socket.recv_from(&mut input) => {
                    let (n, from) = result.unwrap();
                    let _ = conn.recv(&mut input[..n], quiche::RecvInfo { from, to: addr });
                }
                _ = tokio::time::sleep(wait) => conn.on_timeout(),
            }
            if conn.is_closed() || conn.is_draining() {
                return captures;
            }
        }
    });
    Peer { addr, root, task }
}
