# Asterisk B2BUA Deployment

This guide configures a separate Asterisk/PBX VPS for the SIP honeypot B2BUA
path. The honeypot remains the public SIP endpoint. Asterisk should accept SIP and
RTP only from trusted honeypot servers.

## Assumptions

- Honeypot public IP: `107.173.37.88`
- Asterisk/PBX public or private IP: `23.95.193.100`
- Test honeypot SIP port: `15060`
- Production SIP honeypot port: `5060`
- Asterisk RTP range: `10000:20000/udp`
- Honeypot B2BUA RTP relay range: `30000:30100/udp`

Replace these IPs and ports for your deployment.

## Install Asterisk

On the Asterisk VPS:

```bash
apt update
apt install -y asterisk ufw
systemctl enable --now asterisk
systemctl status asterisk --no-pager
asterisk -rx "core show version"
```

The Ubuntu package may log `radcli` warnings about a missing
`/etc/radiusclient-ng/radiusclient.conf`. That is harmless unless RADIUS
auth/accounting is being used.

## Limit systemd Journal Size

Optional but recommended on small VPS disks:

```bash
mkdir -p /etc/systemd/journald.conf.d
cat > /etc/systemd/journald.conf.d/size.conf <<'EOF'
[Journal]
SystemMaxUse=500M
RuntimeMaxUse=100M
MaxRetentionSec=14day
EOF

systemctl restart systemd-journald
journalctl --disk-usage
```

## Firewall: Asterisk VPS

Allow SSH, then allow SIP/RTP only from the honeypot server.

```bash
ufw allow OpenSSH
ufw allow from 107.173.37.88 to any port 5060 proto udp
ufw allow from 107.173.37.88 to any port 10000:20000 proto udp
ufw enable
ufw status numbered
```

For additional honeypot servers, add another pair of SIP/RTP rules for each
honeypot source IP.

## Configure PJSIP

Back up the existing config:

```bash
cp /etc/asterisk/pjsip.conf /etc/asterisk/pjsip.conf.bak.$(date +%Y%m%d-%H%M%S)
```

Append a minimal IP-identified endpoint for the honeypot:

```bash
cat >> /etc/asterisk/pjsip.conf <<'EOF'

; --- knock-knock honeypot inbound trunk ---
[transport-udp]
type=transport
protocol=udp
bind=0.0.0.0:5060

[knock-honeypot]
type=endpoint
transport=transport-udp
context=honeypot-inbound
disallow=all
allow=ulaw
allow=alaw
direct_media=no
rtp_symmetric=yes
force_rport=yes
rewrite_contact=yes
aors=knock-honeypot
identify_by=ip

[knock-honeypot]
type=aor
max_contacts=1

[knock-honeypot]
type=identify
endpoint=knock-honeypot
match=107.173.37.88
EOF
```

Restart Asterisk after adding a new transport:

```bash
systemctl restart asterisk
asterisk -rx "pjsip show transports"
asterisk -rx "pjsip show endpoint knock-honeypot"
```

Expected:

```text
Transport: transport-udp udp 0.0.0.0:5060
Endpoint:  knock-honeypot ... context honeypot-inbound
Identify:  match 107.173.37.88/32
```

`Unavailable` is normal for this IP-identified trunk because the honeypot does not
register.

## Configure Dialplan

Create the recording directory:

```bash
mkdir -p /var/spool/asterisk/honeypot
chown asterisk:asterisk /var/spool/asterisk/honeypot
```

Append a test dialplan:

```bash
cat >> /etc/asterisk/extensions.conf <<'EOF'

[honeypot-inbound]
exten => _X.,1,NoOp(Knock honeypot call to ${EXTEN})
 same => n,Answer()
 same => n,Wait(1)
 same => n,Playback(hello-world)
 same => n,Record(/var/spool/asterisk/honeypot/${CALLERID(num)}-${EPOCH}.wav,3,30,k)
 same => n,Hangup()
EOF

asterisk -rx "dialplan reload"
asterisk -rx "dialplan show honeypot-inbound"
```

`Playback(hello-world)` uses a stock Asterisk prompt. Replace it later with a
custom prompt, installed under `/var/lib/asterisk/sounds/en/` and referenced
without the `.wav` extension.

## Firewall: Honeypot Server

For test mode, allow the alternate SIP port. If the manual test client runs on the
honeypot server and captures RTP, also allow the advertised capture port:

```bash
ufw allow 15060/udp
ufw allow 15060/tcp
ufw allow 40000/udp
```

Allow the Asterisk server to send RTP to the B2BUA relay range:

```bash
ufw allow from 23.95.193.100 to any port 30000:30100 proto udp comment 'asterisk rtp to b2bua'
ufw status numbered
```

For production, keep the Asterisk-to-honeypot RTP rule. The public test SIP port
`15060` can be removed when no longer needed.

## Start a Test SIP Honeypot

If the monitor-managed honeypot is already using port `5060`, run a second test
instance on a different port:

```bash
SIP_PORT=15060 \
PBX_HOST=23.95.193.100 \
PBX_PORT=5060 \
PBX_DIAL_POLICY=all \
SIP_PUBLIC_IP=107.173.37.88 \
PBX_TRACE=true \
SIP_TRACE=true \
python honeypots/sip_honeypot.py
```

Expected startup:

```text
SIP Honeypot Active on Port 15060 (UDP+TCP IPv4+IPv6)
```

## Manual Signaling and RTP Test

Use the manual SIP client from a host that can reach the honeypot test port.

Basic signaling and caller-to-Asterisk silence test:

```bash
python tests/sip_invite_test.py 107.173.37.88 \
  --port 15060 \
  --rtp-seconds 5 \
  --bye-delay 1
```

Generate a simple 8 kHz mono WAV for caller audio:

```bash
apt install -y espeak-ng sox
espeak-ng -w /tmp/hello.wav "Hello world. This is a knock knock SIP audio test."
sox /tmp/hello.wav -r 8000 -c 1 -e signed-integer -b 16 /tmp/hello-8k.wav
```

Bidirectional test:

```bash
python tests/sip_invite_test.py 107.173.37.88 \
  --port 15060 \
  --capture-wav /tmp/from-asterisk.wav \
  --capture-seconds 8 \
  --wav /tmp/hello-8k.wav \
  --rtp-start-delay 4 \
  --bye-delay 1
```

Expected:

- SIP client receives one local `100 Trying`, then `200 OK`.
- `200 OK` SDP advertises the honeypot IP and a `30000:30100` RTP relay port.
- Asterisk creates a recording under `/var/spool/asterisk/honeypot`.
- `/tmp/from-asterisk.wav` contains Asterisk's `hello-world` playback.

Check recordings on the Asterisk VPS:

```bash
ls -lh /var/spool/asterisk/honeypot
file /var/spool/asterisk/honeypot/*.wav
soxi /var/spool/asterisk/honeypot/*.wav 2>/dev/null || true
```

A 44-byte WAV is just an empty header. A larger WAV confirms media reached
`Record()`.

## Useful Asterisk Debugging

Open the Asterisk CLI:

```bash
asterisk -rvvvvv
```

Temporarily enable SIP logging:

```asterisk
pjsip set logger on
pjsip set logger off
```

Temporarily enable RTP logging:

```asterisk
rtp set debug on
rtp set debug off
```

On the honeypot server, verify RTP arrives from Asterisk:

```bash
tcpdump -n udp portrange 30000-30100
```

## Production Notes

- Set `PBX_HOST` on the monitor-managed honeypot service only after test calls pass.
- Use `SIP_PUBLIC_IP` when the honeypot has more than one address or sits behind NAT.
- Keep `PBX_DIAL_POLICY=all` only if all parsed toll-fraud INVITEs should be bridged.
- Use `PBX_DIAL_POLICY=none` to leave PBX config present while disabling bridging.
- Replace `Playback(hello-world)` with a real prompt before production use.
- Add a retention or shipping job for `/var/spool/asterisk/honeypot`.
- Keep Asterisk SIP/RTP firewalled to honeypot IPs only.
