use mumblers::connection::MumbleEvent;
use mumblers::proto::mumble_udp::{Audio, Ping};
use prost::Message;

#[test]
fn test_udp_ping_encoding_decoding() {
    let original_ping = Ping {
        timestamp: 1234567890,
        ..Default::default()
    };

    let mut payload = original_ping.encode_to_vec();
    let mut data = vec![1u8]; // MSG_TYPE_PING
    data.append(&mut payload);

    let decoded_ping = Ping::decode(&data[1..]).unwrap();
    assert_eq!(original_ping.timestamp, decoded_ping.timestamp);
}

#[test]
fn test_udp_audio_encoding_decoding() {
    let original_audio = Audio {
        sender_session: 1,
        frame_number: 100,
        opus_data: vec![0xFF; 100],
        ..Default::default()
    };

    let mut payload = original_audio.encode_to_vec();
    let mut data = vec![0u8]; // MSG_TYPE_AUDIO
    data.append(&mut payload);

    let decoded_audio = Audio::decode(&data[1..]).unwrap();
    assert_eq!(original_audio.sender_session, decoded_audio.sender_session);
    assert_eq!(original_audio.frame_number, decoded_audio.frame_number);
    assert_eq!(original_audio.opus_data, decoded_audio.opus_data);
}

#[test]
fn test_udp_invalid_type() {
    let data = vec![99u8, 0x01, 0x02]; // Unknown type
    let result = Ping::decode(&data[1..]);
    assert!(result.is_err());
}

#[tokio::test]
async fn test_udp_loopback_integration() {
    use tokio::net::UdpSocket;
    use tokio::sync::broadcast;

    let (_event_tx, _event_rx) = broadcast::channel::<MumbleEvent>(10);

    // Bind two sockets for loopback
    let server_socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let client_socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let server_addr = server_socket.local_addr().unwrap();

    // Spawn server task to echo packets
    let server_task = tokio::spawn(async move {
        let mut buf = [0u8; 2048];
        while let Ok((len, addr)) = server_socket.recv_from(&mut buf).await {
            if let Err(_) = server_socket.send_to(&buf[..len], addr).await {
                break;
            }
        }
    });

    // Send a test packet
    let test_data = b"hello udp";
    client_socket.send_to(test_data, server_addr).await.unwrap();

    // Receive echoed packet
    let mut buf = [0u8; 2048];
    let (len, _) = client_socket.recv_from(&mut buf).await.unwrap();
    assert_eq!(&buf[..len], test_data);

    server_task.abort();
}
