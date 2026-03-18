# Integration Guide: Classic RDP Security for knock-knock
#
# This shows the minimal changes to rdp_honeypot.py to capture plaintext
# passwords from legacy (non-NLA) RDP clients.
#
# ============================================================================
# 1. NEW DEPENDENCY
# ============================================================================
#
#   uv pip install cryptography --break-system-packages
#
#   (You likely already have this via paramiko, but the module uses it directly
#    for RSA key generation.)
#
# ============================================================================
# 2. IMPORT — add near the top of rdp_honeypot.py
# ============================================================================

from rdp_classic_security import do_classic_rdp_security, X224_CC_RDP

# ============================================================================
# 3. NEW X.224 CONFIRM — add alongside X224_CC_SSL
# ============================================================================
#
#   X224_CC_RDP is imported from the module above. It's an 11-byte X.224
#   Connection Confirm that selects standard RDP security (no NLA, no SSL).

# ============================================================================
# 4. MODIFY handle_connection() — replace the non-SSL branch
# ============================================================================
#
# CURRENT CODE (around line 275):
#
#     if not (req_protocols & 0x03):
#         # Client doesn't want SSL — emit cookie knock if we have one, then done
#         if cookie_user:
#             trace(session_id, client_ip, 'emit_cookie_knock')
#             knock = {"type": "KNOCK", "proto": "RDP",
#                      "ip": client_ip, "user": cookie_user, "pass": cookie_domain or ''}
#             print(json.dumps(knock), flush=True)
#             final_stage = 'cookie_knock_emitted_non_ssl'
#         else:
#             trace(session_id, client_ip, 'non_ssl_no_cookie')
#             final_stage = 'non_ssl_no_cookie'
#         return
#
#
# REPLACE WITH:
#
#     if not (req_protocols & 0x03):
#         # Client wants standard RDP security — do classic handshake for plaintext creds
#         trace(session_id, client_ip, 'classic_security_path')
#         try:
#             client_sock.sendall(X224_CC_RDP)
#             trace(session_id, client_ip, 'x224_cc_rdp_sent')
#             username, password, domain, classic_status = do_classic_rdp_security(
#                 client_sock, client_ip,
#                 trace_fn=trace,
#                 session_id=session_id,
#             )
#             final_stage = classic_status
#             if username:
#                 knock = {"type": "KNOCK", "proto": "RDP",
#                          "ip": client_ip, "user": username,
#                          "pass": password or ''}
#                 if domain:
#                     knock["domain"] = domain
#                 print(json.dumps(knock), flush=True)
#                 trace(session_id, client_ip, 'emit_classic_knock',
#                       user=username, has_password=bool(password), domain=domain)
#                 final_stage = 'classic_knock_emitted'
#                 creds_captured = True
#             elif cookie_user:
#                 # Classic handshake failed but we have the cookie username
#                 trace(session_id, client_ip, 'emit_cookie_fallback_classic')
#                 knock = {"type": "KNOCK", "proto": "RDP",
#                          "ip": client_ip, "user": cookie_user,
#                          "pass": cookie_domain or ''}
#                 print(json.dumps(knock), flush=True)
#                 final_stage = f'cookie_fallback_after_classic:{classic_status}'
#         except Exception as e:
#             reason = classify_socket_error(e)
#             trace(session_id, client_ip, 'classic_outer_exception',
#                   error=type(e).__name__, reason=reason)
#             if cookie_user:
#                 knock = {"type": "KNOCK", "proto": "RDP",
#                          "ip": client_ip, "user": cookie_user,
#                          "pass": cookie_domain or ''}
#                 print(json.dumps(knock), flush=True)
#             final_stage = f'classic_outer_exception:{reason}'
#         return
#
# ============================================================================
# 5. THAT'S IT
# ============================================================================
#
# The NLA path (req_protocols & 0x03) remains completely unchanged.
# The classic path now attempts the full handshake and falls back to
# cookie-only if anything goes wrong.
#
# The knock JSON for classic captures will have the actual password in the
# "pass" field (plaintext), vs "<hashed>" for NLA captures.
# You could add a "method": "classic" or "method": "nla" field to distinguish.
