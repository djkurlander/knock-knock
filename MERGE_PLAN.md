# Merge Strategy: Master vs Feature/Multiprotocol

## Context

knock-knock.net (master) runs an SSH-only honeypot with a clean, focused UI — 11 panes, ~1,800 lines of frontend code. beta.knock-knock.net (feature/multiprotocol) extends this to 8 protocols (SSH, Telnet, SMTP, RDP, MAIL, FTP, SIP, SMB) with protocol cycling buttons, per-protocol leaderboards, protocol badges, and a Proto Stats pane — 12 panes, ~2,800 lines of frontend. The feature branch is 54 commits ahead; master has 0 commits not in feature (clean fast-forward).

The dilemma: the simple UI is elegant, the multiprotocol data is valuable, and maintaining two divergent codebases is unsustainable for a solo developer.

## Recommendation: Merge + Auto-Detecting Classic Mode

**Insight:** The multiprotocol frontend *already works identically to the classic view* when the protocol filter is on "ALL." The only visual differences are protocol cycle buttons, the Proto Stats pane, and protocol badges in the feed. When only one protocol is enabled, those elements are meaningless — so hide them automatically.

**The rule:** The frontend already receives `enabled_protocols` from the server on WebSocket connect. If `enabled_protocols.length === 1`, apply classic mode. If `> 1`, show the full multiprotocol UI. No toggles, no URL params, no user decisions — the UI adapts to the server config.

## Implementation

### Step 1: Merge feature/multiprotocol into master
```bash
git checkout master
git merge --ff-only feature/multiprotocol
```

### Step 2: Add auto-detecting classic mode (~25 lines in index.html)

**CSS (~10 lines):**
```css
body.classic-mode .proto-cycle-btn { display: none !important; }
body.classic-mode #d-box-proto { display: none !important; }
body.classic-mode #m-pane-proto { display: none !important; }
body.classic-mode .proto-badge { display: none !important; }
/* Hide Proto Stats nav items in both desktop and mobile nav */
```

**JS (~15 lines):**
In the WebSocket `init_stats` handler (where `enabled_protocols` is already received):
```javascript
// Auto-detect classic mode based on server config
const classicMode = (data.enabled_protocols || []).length <= 1;
document.body.classList.toggle('classic-mode', classicMode);
// Adjust pane count for mobile dots / desktop nav if needed
```

No localStorage, no toggle button, no URL params. Pure server-driven.

### Step 3: Adjust navigation pane counts

When classic mode is active, the Proto Stats pane is hidden. The desktop nav and mobile dot indicators need to account for this:
- Desktop: hide the Proto Stats nav item (CSS handles this)
- Mobile: hide the corresponding dot and adjust swipe/snap behavior
- `dJump()` / mobile pane index may need a small guard if Proto Stats pane index is referenced

## Why this wins

1. **Zero code duplication** — one index.html, one backend, one branch
2. **Zero configuration** — no toggles, no URL params; UI auto-adapts
3. **Correct by construction** — single-protocol deployments get a clean UI because the protocol UI *has nothing to show*
4. **Fast-forward merge** — no conflicts, all 54 commits ship to production
5. **Trivial implementation** — ~25 lines of CSS+JS
6. **Zero maintenance overhead** — every future fix applies to both modes automatically

## Files to Modify

| File | Change |
|------|--------|
| `index.html` | ~10 lines CSS for `.classic-mode` rules, ~15 lines JS for auto-detection in `init_stats` handler |
| No backend changes | main.py, monitor.py, constants.py already complete on feature branch |

## Verification

1. Merge: `git checkout master && git merge --ff-only feature/multiprotocol`
2. Multi-protocol test: deploy with multiple protocols enabled → confirm full UI (cycle buttons, Proto Stats, badges all visible)
3. Single-protocol test: set `ENABLED_PROTOCOLS=SSH` in env → restart monitor → reload page → confirm classic mode (no cycle buttons, no Proto Stats pane, no protocol badges)
4. Mobile: confirm Proto Stats nav dot hidden in classic mode, swipe navigation still works correctly
5. Verify leaderboards still aggregate correctly in both modes
