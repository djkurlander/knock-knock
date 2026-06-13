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

Use `MixMonitor()` rather than `Record()`. `Record()` starts recording only when
that dialplan application runs; `MixMonitor()` records the call audio while the
rest of the dialplan continues, so it can capture both Asterisk playback and
caller audio in one mixed file.

Append a dialplan:

```bash
cat >> /etc/asterisk/extensions.conf <<'EOF'

[honeypot-inbound]
exten => _X.,1,NoOp(Knock honeypot call to ${EXTEN})
 same => n,Set(KNOCK_BRIDGE_ID=${PJSIP_HEADER(read,X-Bridge-ID)})
 same => n,Set(KNOCK_SRC_IP=${PJSIP_HEADER(read,X-Source-IP)})
 same => n,Set(KNOCK_SOURCE_ID=${PJSIP_HEADER(read,X-Source-ID)})
 same => n,Set(KNOCK_LIVE=${PJSIP_HEADER(read,X-Live-Outbound)})
 same => n,Set(KNOCK_LIVE_PERMIT_ID=${PJSIP_HEADER(read,X-Live-Permit-ID)})
 same => n,Set(KNOCK_LIVE_MAX=${PJSIP_HEADER(read,X-Live-Max-Seconds)})
 same => n,ExecIf($["${KNOCK_BRIDGE_ID}" = ""]?Set(KNOCK_BRIDGE_ID=no-bridge-${UNIQUEID}))
 same => n,ExecIf($["${KNOCK_SOURCE_ID}" = ""]?Set(KNOCK_SOURCE_ID=unknown))
 same => n,ExecIf($["${KNOCK_LIVE_MAX}" = ""]?Set(KNOCK_LIVE_MAX=45))
 same => n,GotoIf($["${KNOCK_LIVE}" = "1"]?live)
 same => n,Progress()
 same => n,Ringing()
 same => n,Wait(3)
 same => n,Answer()
 same => n,MixMonitor(/var/spool/asterisk/honeypot/${KNOCK_SOURCE_ID}-${KNOCK_BRIDGE_ID}-${CALLERID(num)}-${EPOCH}.wav)
 same => n,Wait(1)
 same => n,Playback(/var/lib/asterisk/sounds/en/custom/freesound_community-hello-91045)
 same => n,Wait(30)
 same => n,StopMixMonitor()
 same => n,Hangup()

 same => n(live),Answer()
 same => n,MixMonitor(/var/spool/asterisk/live-outbound/${KNOCK_SOURCE_ID}-${KNOCK_BRIDGE_ID}-${KNOCK_LIVE_PERMIT_ID}-${CALLERID(num)}-${EXTEN}-${EPOCH}.wav)
 same => n,Set(CALLERID(num)=<VALID_TELNYX_OR_VERIFIED_NUMBER>)
 same => n,Set(CALLERID(name)=<VALID_TELNYX_OR_VERIFIED_NUMBER>)
 same => n,Set(CALLERID(pres)=prohib)
 same => n,Dial(PJSIP/${EXTEN}@telnyx,${KNOCK_LIVE_MAX})
 same => n,StopMixMonitor()
 same => n,Hangup()
EOF

asterisk -rx "dialplan reload"
asterisk -rx "dialplan show honeypot-inbound"
```

This sends early progress/ringing and then answers after three seconds. For
maximum capture rate, remove `Progress()`, `Ringing()`, and the pre-answer
`Wait(3)` so Asterisk answers immediately. Long pre-answer delays can cause
scanners to hang up before media is captured.

`X-Bridge-ID` is sent by the honeypot B2BUA. Including it in the
`MixMonitor()` filename makes Asterisk recordings correlate back to SIP knock
rows that have `sip_pbx_bridge_id`.

The `live` branch is only used when the honeypot B2BUA consumes an exact
one-shot Redis permit. The default path remains answer/play/record only.
`<VALID_TELNYX_OR_VERIFIED_NUMBER>` must be replaced before enabling live
outbound calls.

## Install a Custom Playback Prompt

Asterisk sends RTP using the codec negotiated with the caller, not WAV or MP3 as
wire formats. The baseline PJSIP endpoint above allows `ulaw` and `alaw`, so keep
native `.ul` and `.al` prompt files alongside the source WAV. The source WAV is
still useful for inspection and for regenerating other formats.

Install `sox` with MP3 support if your source prompt is MP3:

```bash
apt install -y sox libsox-fmt-mp3
mkdir -p /var/lib/asterisk/sounds/en/custom
```

Convert an MP3 prompt to 8 kHz mono PCM WAV:

```bash
sox /path/to/freesound_community-hello-91045.mp3 \
  -r 8000 -c 1 -b 16 \
  /var/lib/asterisk/sounds/en/custom/freesound_community-hello-91045.wav
```

Create native ulaw/alaw files. This Asterisk package recognizes these raw codec
formats by `.ul` and `.al` extensions:

```bash
sox /var/lib/asterisk/sounds/en/custom/freesound_community-hello-91045.wav \
  -t ul /var/lib/asterisk/sounds/en/custom/freesound_community-hello-91045.ul

sox /var/lib/asterisk/sounds/en/custom/freesound_community-hello-91045.wav \
  -t al /var/lib/asterisk/sounds/en/custom/freesound_community-hello-91045.al

chown asterisk:asterisk /var/lib/asterisk/sounds/en/custom/freesound_community-hello-91045.*
chmod 644 /var/lib/asterisk/sounds/en/custom/freesound_community-hello-91045.*
```

Some tools/examples use `.ulaw` and `.alaw` filenames, but this Asterisk package
looked for codec-native files by `.ul` / `.al`. If relative playback such as
`Playback(custom/freesound_community-hello-91045)` cannot find the file, use the
absolute basename shown in the dialplan above:

```asterisk
same => n,Playback(/var/lib/asterisk/sounds/en/custom/freesound_community-hello-91045)
```

Do not include the file extension in `Playback()`.

Verify the files:

```bash
find /var/lib/asterisk/sounds/en/custom -name 'freesound_community-hello-91045*' -ls
file /var/lib/asterisk/sounds/en/custom/freesound_community-hello-91045.wav
asterisk -rx "core show file formats" | grep -E 'ulaw|alaw| ul | al |wav'
```

## Optional Manual Outbound Test Trunks

The honeypot dialplan above does not call the dialed PSTN/VoIP target. For
manual research calls, use a separate authenticated softphone endpoint and a
separate outbound trunk context. This keeps the honeypot path isolated while
allowing controlled calls from Zoiper or another softphone through Asterisk.

Create the outbound recording directory:

```bash
mkdir -p /var/spool/asterisk/outbound-test
chown asterisk:asterisk /var/spool/asterisk/outbound-test
mkdir -p /var/spool/asterisk/live-outbound
chown asterisk:asterisk /var/spool/asterisk/live-outbound
```

For a softphone that registers to Asterisk, use the same name for the endpoint
and AOR. This avoids registrar/AOR lookup failures such as `AOR '' not found`.

```ini
; --- manual Telnyx test softphone ---
[testphone-telnyx-auth]
type=auth
auth_type=userpass
username=testphone-telnyx
password=<STRONG_PASSWORD>

[testphone-telnyx]
type=aor
max_contacts=1
remove_existing=yes

[testphone-telnyx]
type=endpoint
transport=transport-udp
context=outbound-test-telnyx
disallow=all
allow=ulaw
allow=alaw
auth=testphone-telnyx-auth
aors=testphone-telnyx
direct_media=no
rtp_symmetric=yes
force_rport=yes
rewrite_contact=yes
```

Configure Zoiper with:

```text
Username: testphone-telnyx
Auth username: testphone-telnyx
Host: 23.95.193.100:5060
Transport: UDP
STUN: off
Outbound proxy: blank
```

Keep the Asterisk firewall limited to your current softphone source IP.

### Telnyx PJSIP Endpoint

Add a Telnyx trunk endpoint. Use the SIP username, password, and server from the
Telnyx portal. If Telnyx gives you a regional SIP server, use that server instead
of `sip.telnyx.com`.

```ini
[telnyx-auth]
type=auth
auth_type=userpass
username=<TELNYX_SIP_USERNAME>
password=<TELNYX_SIP_PASSWORD>

[telnyx-aor]
type=aor
contact=sip:sip.telnyx.com:5060
qualify_frequency=60

[telnyx]
type=endpoint
transport=transport-udp
context=from-telnyx
disallow=all
allow=ulaw
allow=alaw
outbound_auth=telnyx-auth
aors=telnyx-aor
direct_media=no
rtp_symmetric=yes
force_rport=yes
rewrite_contact=yes
send_pai=yes
send_rpid=yes
trust_id_outbound=yes
```

Unlike a registering softphone endpoint, the Telnyx trunk can use a separate
static AOR name such as `telnyx-aor` because Asterisk is dialing out to that
contact; Telnyx is not registering as a local endpoint.

Reload and verify:

```bash
asterisk -rx "pjsip reload"
asterisk -rx "pjsip show endpoint telnyx"
asterisk -rx "pjsip show aor telnyx-aor"
```

### Telnyx Outbound Dialplan

This context accepts US/NANP calls and common international formats, normalizing
international numbers to E.164 without the leading `+` before dialing Telnyx.
Use a valid Telnyx-owned or verified number as the caller ID even when requesting
privacy.

```asterisk
[outbound-test-telnyx]
exten => _1NXXNXXXXXX,1,Gosub(outbound-test-call-telnyx,s,1(${EXTEN}))
 same => n,Hangup()

exten => _NXXNXXXXXX,1,Gosub(outbound-test-call-telnyx,s,1(1${EXTEN}))
 same => n,Hangup()

exten => _+X.,1,Gosub(outbound-test-call-telnyx,s,1(${EXTEN:1}))
 same => n,Hangup()

exten => _011X.,1,Gosub(outbound-test-call-telnyx,s,1(${EXTEN:3}))
 same => n,Hangup()

exten => _00X.,1,Gosub(outbound-test-call-telnyx,s,1(${EXTEN:2}))
 same => n,Hangup()

exten => _Z.,1,Gosub(outbound-test-call-telnyx,s,1(${EXTEN}))
 same => n,Hangup()

exten => _X.,1,NoOp(Blocked Telnyx outbound test attempt ${EXTEN})
 same => n,Hangup()

[outbound-test-call-telnyx]
exten => s,1,NoOp(Manual Telnyx outbound test to ${ARG1})
 same => n,MixMonitor(/var/spool/asterisk/outbound-test/telnyx-${ARG1}-${EPOCH}.wav)
 same => n,Set(CALLERID(num)=<VALID_TELNYX_OR_VERIFIED_NUMBER>)
 same => n,Set(CALLERID(name)=<VALID_TELNYX_OR_VERIFIED_NUMBER>)
 same => n,Set(CALLERID(pres)=prohib)
 same => n,Dial(PJSIP/${ARG1}@telnyx,45)
 same => n,StopMixMonitor()
 same => n,Return()
```

`CALLERID(pres)=prohib` makes Asterisk send an anonymous presentation with
identity still asserted to Telnyx, for example `From: "Anonymous"
<sip:anonymous@anonymous.invalid>`, `Privacy: id`, and `P-Asserted-Identity`
containing the valid caller ID. Do not also add a separate `Privacy: id` header
unless testing requires it, or the outbound INVITE may contain duplicate privacy
headers.

The `_Z.` pattern permits broad international dialing from this context. Keep the
softphone endpoint protected with a strong password and firewall rules limited to
trusted source IPs.

Reload after editing:

```bash
asterisk -rx "dialplan reload"
asterisk -rx "dialplan show outbound-test-telnyx"
```

### Play a Captured Bot Tone to the Outbound Target

To replay a captured honeypot recording to the called target after answer, use
the `U()` option on `Dial()` and a playback subroutine. Convert the captured file
to an Asterisk sound first:

```bash
sox /var/spool/asterisk/honeypot/7ebf6fd926-10000-1781058597.wav \
  -r 8000 -c 1 -b 16 \
  /var/lib/asterisk/sounds/en/custom/bot-tone.wav
chown asterisk:asterisk /var/lib/asterisk/sounds/en/custom/bot-tone.wav
chmod 644 /var/lib/asterisk/sounds/en/custom/bot-tone.wav
```

Then change the Telnyx dial line and add the playback context:

```asterisk
same => n,Dial(PJSIP/${ARG1}@telnyx,45,U(play-bot-tone^s^1))

[play-bot-tone]
exten => s,1,NoOp(Playing captured bot tone to answered Telnyx leg)
 same => n,Playback(/var/lib/asterisk/sounds/en/custom/bot-tone)
 same => n,Return()
```

Do not include the file extension in `Playback()`.

## One-Shot Live Outbound Permits

By default, SIP INVITEs follow the normal configured behavior: fake answer,
Asterisk recording/playback, or PBX bridging according to `PBX_DIAL_POLICY`.
For rare investigations, a one-shot permit can override that flow for one exact
source IP and parsed dial number. A permit may also use `*` as the source IP to
match the next source that targets that exact dial number. When a matching INVITE
arrives, the permit is atomically consumed, the call is sent to Asterisk with
live outbound headers, and the Asterisk `live` branch dials the requested target
through Telnyx.

The permit is fail-closed:

- Redis must be reachable.
- `PBX_HOST` must be configured.
- The strict E.164 dial number must match exactly.
- The source IP must match exactly, unless the permit source is `*`.
- If both exact and wildcard permits exist for the same number, exact wins.
- The permit is consumed once.
- A global active-call lock allows only one live outbound bridge at a time.
- `sip_pbx_live_permit_id` is stored on the matching `knocks_sip` row.

Create a permit from the honeypot server:

```bash
python extras/sip_permit.py create 172.110.223.203 +442039960320 \
  --permit-id manual-20260611-001 \
  --hours 24 \
  --max-seconds 45 \
  --note "watch ab00day campaign"
```

Create a one-shot campaign permit for any source IP hitting the exact number:

```bash
python extras/sip_permit.py create '*' +442039960320 \
  --permit-id manual-20260611-campaign \
  --hours 24 \
  --max-seconds 45 \
  --note "next source in campaign"
```

List pending permits:

```bash
python extras/sip_permit.py list
```

Delete a permit before it is consumed:

```bash
python extras/sip_permit.py delete 172.110.223.203 +442039960320
```

Permit dial numbers must be strict E.164, for example `+442039960320`.
Formatted numbers, bare country-code numbers, `0044...`, and `01144...` are
rejected instead of normalized. Runtime caps are controlled by:

```text
SIP_LIVE_PERMIT_MAX_TTL=172800
SIP_LIVE_MAX_CALL_SECONDS_CAP=90
```

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
SOURCE_ID=LA1 \
PBX_TRACE=true \
SIP_TRACE=true \
python honeypots/sip_honeypot.py
```

`SOURCE_ID` is sent only to Asterisk as `X-Source-ID` and is used as the first
recording filename component. If it is unset, recordings use `unknown`.

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
- Asterisk creates a mixed recording under `/var/spool/asterisk/honeypot`.
- The recording filename starts with `SOURCE_ID` from `X-Source-ID`, then the bridge ID from `X-Bridge-ID`.
- `/tmp/from-asterisk.wav` contains Asterisk's custom playback prompt.

Check recordings on the Asterisk VPS:

```bash
ls -lh /var/spool/asterisk/honeypot
file /var/spool/asterisk/honeypot/*.wav
soxi /var/spool/asterisk/honeypot/*.wav 2>/dev/null || true
```

A 44-byte WAV is just an empty header. A larger WAV confirms media reached
`MixMonitor()`.

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

If `Playback()` fails with `File ... does not exist in any format`, verify both
the absolute path in the dialplan and the codec-native prompt files:

```bash
find /var/lib/asterisk/sounds/en/custom -name 'freesound_community-hello-91045*' -ls
asterisk -rx "core show file formats" | grep -E 'ulaw|alaw| ul | al |wav'
```

If relative `Playback(custom/name)` fails despite the file appearing in
`core show sounds`, use an absolute basename:

```asterisk
same => n,Playback(/var/lib/asterisk/sounds/en/custom/freesound_community-hello-91045)
```

## Capture Bot Audio (Raw RTP Dump)

The B2BUA can save the attacker's inbound RTP — the pristine source-side copy of
the audio the bot streams after answer — to a per-bridge `.rtp` file. This is the
same media Asterisk records as the `rx` leg, but captured on the honeypot before
any jitter buffer or transcode, with no `tx`/PBX audio mixed in. It is opt-in and
applies to every bridged call, not only live-permit calls, so a large corpus of
bot beacons accumulates passively.

Set on the honeypot (monitor-managed service or a test instance). Use full-line
comments only — `.env` is read by systemd `EnvironmentFile` / Docker `env_file`,
which (unlike a shell `source`) keep any trailing `# ...` as part of the value:

```text
# Directory for per-bridge RTP dumps; unset/empty disables capture.
PBX_RTP_DUMP_DIR=data/rtp_dumps
# Per-bridge packet cap (~240s at 50pps).
PBX_RTP_DUMP_MAX_PACKETS=12000
```

Filenames mirror the Asterisk `MixMonitor` convention so they correlate:
`${SOURCE_ID}-${BRIDGE_ID}-${PERMIT_ID}-${CLIENT_IP}-${DIAL_NUMBER}-${EPOCH}.rtp`.
The `BRIDGE_ID` maps back to `knocks_sip.sip_pbx_bridge_id`.

Convert a dump to a gap-accurate 8 kHz WAV (silence is inserted for lost packets
from RTP timestamps, so on/off beacon timing is preserved):

```bash
python extras/sip_rtp_to_wav.py data/rtp_dumps/LA1-<bridge>-....rtp
python extras/sip_rtp_to_wav.py data/rtp_dumps/LA1-<bridge>-....rtp --info  # stats only
```

Add a retention/shipping job for `PBX_RTP_DUMP_DIR` as with the Asterisk
recordings.

## Production Notes

- Set `PBX_HOST` on the monitor-managed honeypot service only after test calls pass.
- Use `SIP_PUBLIC_IP` when the honeypot has more than one address or sits behind NAT.
- Keep `PBX_DIAL_POLICY=all` only if all parsed toll-fraud INVITEs should be bridged.
- Use `PBX_DIAL_POLICY=none` to leave PBX config present while disabling bridging.
- Use a custom `Playback()` prompt with `.ul` and `.al` native files before
  production use.
- Add a retention or shipping job for `/var/spool/asterisk/honeypot`.
- Keep Asterisk SIP/RTP firewalled to honeypot IPs only.
