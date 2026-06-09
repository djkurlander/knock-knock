#!/usr/bin/env python3
"""Manual SIP INVITE smoke client for the SIP honeypot.

This is intentionally not a pytest test. Run it from a host that can reach the
honeypot test SIP port.
"""

import argparse
import audioop
import re
import socket
import threading
import time
import uuid
import wave


def _build_invite(target_ip, target_port, dial_number, local_ip, local_port, local_rtp_port, call_id, tag):
    branch = "z9hG4bK" + uuid.uuid4().hex[:12]
    sdp = (
        "v=0\r\n"
        f"o=- 1 1 IN IP4 {local_ip}\r\n"
        "s=test\r\n"
        f"c=IN IP4 {local_ip}\r\n"
        "t=0 0\r\n"
        f"m=audio {local_rtp_port} RTP/AVP 0 8\r\n"
        "a=rtpmap:0 PCMU/8000\r\n"
        "a=rtpmap:8 PCMA/8000\r\n"
    )
    return (
        f"INVITE sip:{dial_number}@{target_ip} SIP/2.0\r\n"
        f"Via: SIP/2.0/UDP {local_ip}:{local_port};branch={branch}\r\n"
        "Max-Forwards: 70\r\n"
        f'From: "test" <sip:100@{local_ip}>;tag={tag}\r\n'
        f"To: <sip:{dial_number}@{target_ip}>\r\n"
        f"Call-ID: {call_id}\r\n"
        "CSeq: 1 INVITE\r\n"
        f"Contact: <sip:100@{local_ip}:{local_port}>\r\n"
        "Content-Type: application/sdp\r\n"
        f"Content-Length: {len(sdp.encode())}\r\n"
        "\r\n" + sdp
    )


def _build_ack_or_bye(method, target_ip, dial_number, local_ip, local_port, call_id, tag, to_header, cseq):
    branch = "z9hG4bK" + uuid.uuid4().hex[:12]
    return (
        f"{method} sip:{dial_number}@{target_ip} SIP/2.0\r\n"
        f"Via: SIP/2.0/UDP {local_ip}:{local_port};branch={branch}\r\n"
        "Max-Forwards: 70\r\n"
        f'From: "test" <sip:100@{local_ip}>;tag={tag}\r\n'
        f"To: {to_header}\r\n"
        f"Call-ID: {call_id}\r\n"
        f"CSeq: {cseq} {method}\r\n"
        f"Contact: <sip:100@{local_ip}:{local_port}>\r\n"
        "Content-Length: 0\r\n\r\n"
    )


def _parse_response_rtp_target(text):
    conn_ip = None
    audio_port = None
    for raw_line in text.replace("\r\n", "\n").split("\n"):
        line = raw_line.strip()
        if line.startswith("c="):
            parts = line.split()
            if len(parts) >= 3:
                conn_ip = parts[2]
        elif line.startswith("m=audio"):
            parts = line.split()
            if len(parts) >= 2 and parts[1].isdigit():
                audio_port = int(parts[1])
    if conn_ip and audio_port:
        return conn_ip, audio_port
    return None


def _send_rtp_packet(sock, target, sequence, timestamp, ssrc, payload):
    header = bytes([
        0x80,
        0x00,
        (sequence >> 8) & 0xff,
        sequence & 0xff,
        (timestamp >> 24) & 0xff,
        (timestamp >> 16) & 0xff,
        (timestamp >> 8) & 0xff,
        timestamp & 0xff,
        (ssrc >> 24) & 0xff,
        (ssrc >> 16) & 0xff,
        (ssrc >> 8) & 0xff,
        ssrc & 0xff,
    ])
    sock.sendto(header + payload, target)


def _send_pcmu_silence(target, duration, ptime, start_delay=0.0):
    if duration <= 0:
        return
    if start_delay > 0:
        print(f"Waiting {start_delay:.1f}s before sending RTP")
        time.sleep(start_delay)
    rtp = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sequence = 0
    timestamp = 0
    ssrc = 0x12345678
    payload_len = max(1, int(8000 * (ptime / 1000.0)))
    payload = b"\xff" * payload_len  # PCMU silence
    deadline = time.time() + duration
    interval = max(0.005, ptime / 1000.0)
    print(f"Sending RTP PCMU silence to {target[0]}:{target[1]} for {duration:.1f}s")
    try:
        while time.time() < deadline:
            _send_rtp_packet(rtp, target, sequence, timestamp, ssrc, payload)
            sequence = (sequence + 1) & 0xffff
            timestamp = (timestamp + payload_len) & 0xffffffff
            time.sleep(interval)
    finally:
        rtp.close()


def _send_wav_as_pcmu(target, wav_path, ptime, start_delay=0.0):
    if start_delay > 0:
        print(f"Waiting {start_delay:.1f}s before sending RTP")
        time.sleep(start_delay)
    rtp = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sequence = 0
    timestamp = 0
    ssrc = 0x12345678
    frame_samples = max(1, int(8000 * (ptime / 1000.0)))
    interval = max(0.005, ptime / 1000.0)
    try:
        with wave.open(wav_path, "rb") as wf:
            channels = wf.getnchannels()
            sample_width = wf.getsampwidth()
            rate = wf.getframerate()
            if channels != 1 or rate != 8000 or sample_width not in (1, 2):
                raise ValueError(
                    f"{wav_path} must be mono 8000 Hz PCM WAV with 8-bit or 16-bit samples "
                    f"(got channels={channels}, rate={rate}, sample_width={sample_width})"
                )
            print(f"Sending WAV as PCMU RTP to {target[0]}:{target[1]}: {wav_path}")
            while True:
                pcm = wf.readframes(frame_samples)
                if not pcm:
                    break
                if sample_width == 1:
                    pcm = audioop.bias(pcm, 1, -128)
                    pcm = audioop.lin2lin(pcm, 1, 2)
                payload = audioop.lin2ulaw(pcm, 2)
                _send_rtp_packet(rtp, target, sequence, timestamp, ssrc, payload)
                sequence = (sequence + 1) & 0xffff
                timestamp = (timestamp + len(payload)) & 0xffffffff
                time.sleep(interval)
    finally:
        rtp.close()


def _capture_pcmu_to_wav(sock, output_path, stop_event):
    frames = []
    sock.settimeout(0.2)
    print(f"Capturing inbound RTP to {output_path}")
    while not stop_event.is_set():
        try:
            packet, _addr = sock.recvfrom(4096)
        except socket.timeout:
            continue
        except OSError:
            break
        if len(packet) <= 12:
            continue
        payload = packet[12:]
        try:
            frames.append(audioop.ulaw2lin(payload, 2))
        except Exception:
            continue
    if not frames:
        print(f"No inbound RTP captured for {output_path}")
        return
    with wave.open(output_path, "wb") as wf:
        wf.setnchannels(1)
        wf.setsampwidth(2)
        wf.setframerate(8000)
        wf.writeframes(b"".join(frames))
    print(f"Wrote inbound RTP capture: {output_path}")


def _stop_after(stop_event, seconds):
    if seconds > 0:
        time.sleep(seconds)
        stop_event.set()


def main():
    parser = argparse.ArgumentParser(description="Send one SIP INVITE to a honeypot and print responses.")
    parser.add_argument("target_ip", help="Honeypot IP or hostname")
    parser.add_argument("--port", type=int, default=15060, help="Honeypot SIP port")
    parser.add_argument("--dial", default="+12025550123", help="Dial target in the SIP URI")
    parser.add_argument("--rtp-port", type=int, default=40000, help="Advertised local RTP port")
    parser.add_argument("--timeout", type=float, default=10.0, help="Receive timeout in seconds")
    parser.add_argument("--bye-delay", type=float, default=3.0, help="Seconds to wait between ACK and BYE")
    parser.add_argument("--rtp-seconds", type=float, default=3.0, help="Seconds of PCMU silence to send after 200 OK")
    parser.add_argument("--rtp-start-delay", type=float, default=0.0, help="Seconds to wait after ACK before sending RTP")
    parser.add_argument("--ptime", type=float, default=20.0, help="RTP packetization time in milliseconds")
    parser.add_argument("--wav", help="Mono 8 kHz PCM WAV to send as PCMU RTP instead of silence")
    parser.add_argument("--capture-wav", help="Write inbound PCMU RTP from the honeypot/PBX to this WAV")
    parser.add_argument("--capture-seconds", type=float, default=8.0, help="Maximum seconds to capture inbound RTP")
    args = parser.parse_args()

    rtp_recv_sock = None
    capture_stop = None
    capture_thread = None
    if args.capture_wav:
        rtp_recv_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        rtp_recv_sock.bind(("0.0.0.0", args.rtp_port))
        capture_stop = threading.Event()
        capture_thread = threading.Thread(
            target=_capture_pcmu_to_wav,
            args=(rtp_recv_sock, args.capture_wav, capture_stop),
            daemon=True,
        )
        capture_thread.start()
        threading.Thread(target=_stop_after, args=(capture_stop, args.capture_seconds), daemon=True).start()

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind(("0.0.0.0", 0))
    sock.connect((args.target_ip, args.port))
    local_ip, local_port = sock.getsockname()

    call_id = f"{uuid.uuid4().hex}@test"
    tag = uuid.uuid4().hex[:10]
    invite = _build_invite(
        args.target_ip,
        args.port,
        args.dial,
        local_ip,
        local_port,
        args.rtp_port,
        call_id,
        tag,
    )

    print(f"Sending INVITE from {local_ip}:{local_port} to {args.target_ip}:{args.port}")
    sock.send(invite.encode())
    sock.settimeout(args.timeout)

    to_header = None
    rtp_target = None
    while True:
        try:
            data = sock.recv(65535)
        except socket.timeout:
            print("Timed out waiting for SIP response")
            break

        text = data.decode("utf-8", errors="replace")
        print("\n--- response ---")
        print(text)

        m = re.search(r"^To:\s*(.+)$", text, re.I | re.M)
        if m:
            to_header = m.group(1).strip()

        if text.startswith("SIP/2.0 200"):
            rtp_target = _parse_response_rtp_target(text)
            if not to_header:
                print("No To header in 200 OK; not sending ACK/BYE")
                break
            ack = _build_ack_or_bye(
                "ACK", args.target_ip, args.dial, local_ip, local_port, call_id, tag, to_header, 1
            )
            print("\nSending ACK")
            sock.send(ack.encode())
            if rtp_target:
                if args.wav:
                    _send_wav_as_pcmu(rtp_target, args.wav, args.ptime, args.rtp_start_delay)
                else:
                    _send_pcmu_silence(rtp_target, args.rtp_seconds, args.ptime, args.rtp_start_delay)
            else:
                print("No RTP target found in 200 OK SDP")
            if args.bye_delay > 0:
                time.sleep(args.bye_delay)

            bye = _build_ack_or_bye(
                "BYE", args.target_ip, args.dial, local_ip, local_port, call_id, tag, to_header, 2
            )
            print("Sending BYE")
            sock.send(bye.encode())
            break

    sock.close()
    if capture_stop:
        capture_stop.set()
    if rtp_recv_sock:
        rtp_recv_sock.close()
    if capture_thread:
        capture_thread.join(timeout=2)


if __name__ == "__main__":
    main()
