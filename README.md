# Proof Gatekeeper Agent — Deploy Guide (for ted)

Agent is **built and fully tested locally** (14/14 tests: all 7 trap types, preflight, HMAC, idempotency, proofs verify against the official VK). It needs a public always-awake home + 3 values from you. Total time: ~5 minutes.

## Step 1 — Railway (stable endpoint, ~2 min)

1. Go to **railway.app** → **Login with GitHub** (use the same GitHub you connect to Agent Games).
2. New Project → **Deploy from GitHub repo** → use the repo Muse prepared for this agent (ask Muse for the repo link if you don't have it yet) — Railway detects the `Dockerfile` automatically.
   - No repo yet? Alternative: in the Railway project → **+ New → Empty Service → Settings → Source Repo**; or use the Railway CLI path Muse gives you.
3. In the service → **Variables**, add:
   - `AGENT_GAMES_HMAC_SECRET` = *(fill after Step 2 — dashboard Rotate Secret value)*
   - `KURIER_API_KEY` = *(your kurier.xyz mainnet key — optional but recommended)*
   - `SEEN_PATH` = `/data/seen.json`
4. **Volumes**: add a volume mounted at `/data` (so the PROOF_REUSED seen-set survives redeploys).
5. **Networking → Public Networking → Generate Domain**. Your endpoint is:
   `https://<generated-domain>/agent`
6. Check `https://<generated-domain>/health` shows `{"ok":true,...}`.

> New Railway accounts get a one-time **$5 trial credit (30 days)** — enough for the whole season (rounds end 20 Nov). After that it's $5/mo Hobby if you keep it. The service never sleeps on Railway. **Do NOT use Render free** (sleeps after 15 min; cold start eats the 60 s task deadline).

## Step 2 — Agent Games dashboard (register the agent, before 17:30 WIB today for Round 3)

In your logged-in dashboard (account @tedx_gg):

- **Agent name:** `horniboi-gatekeeper` (if taken, `horniboi-gk-01`)
- **Event:** Proof Gatekeeper
- **Endpoint URL:** `https://<generated-domain>/agent` ← the FULL path including `/agent`, exactly as generated. A root URL without `/agent` fails preflight.
- Connect **GitHub** and **wallet** on your profile if not done (prize eligibility).
- Click **Rotate Secret** on the agent → copy the plaintext shown **once**.

## Step 3 — Send back to Muse (secure channel, NOT plain chat if avoidable)

1. The **Railway domain** (public, safe anywhere).
2. The **HMAC secret** from Rotate Secret — via Secure Vault capture. If lost: Rotate Secret again (the old one stops working immediately) and update the Railway variable to match.
3. Your **Kurier API key** (kurier.xyz → sign up → mainnet API key; free, ~2 min) — same secure channel; put it in the Railway variables too (Step 1.3), or send it and Muse will tell you where it goes.

After that: Muse runs **practice dispatches** with you (10/hour, unscored) to burn down the remaining encoding unknowns (see `../FEASIBILITY.md` §4) **before** Round 3 opens at **17:30 WIB today**. Entries lock while a round is open — registration must be finished before then to play R03; otherwise the debut is R04 (16 Nov, 17:30 WIB).

## Local run / test

```bash
npm install
AGENT_GAMES_HMAC_SECRET=<any-64-hex-for-local> node server.js   # listens on $PORT or 8080
npm test                                                          # synthetic tasks for all trap types
```

## How it behaves (one paragraph)

Verifies the platform's HMAC on the raw body before parsing → deterministic checks in trap-priority order (VK → threshold → expiry → recipient → amount → reuse) → generates the Groth16 proof locally with the official artifacts (the circuit itself refuses to prove a wrong decision) → optionally submits to Kurier for a finalized on-chain record → replies signed, within ~2–5 s typical. Fails closed (REJECT) on any error; task retries get the cached identical response.
