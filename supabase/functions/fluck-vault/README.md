# Fluck vault and CVV entry

The page on which the owner types a password, a card, or the security code for one purchase. Fluck
texts a link, the value is typed here once, and the DGX collects it. Nothing sensitive travels
through Messages, and nothing sensitive is ever held by this function.

## The one property everything else follows from

**This function cannot read what it stores.** The page encrypts in the browser to a public key whose
private half lives only on the DGX, and the function writes the opaque result into a staging table
the DGX drains. It has no grant on `public.secrets`, it never calls `encrypt_text` or
`decrypt_text`, and it cannot mint a link. A full compromise of the function, or of the project's
service role key, yields a queue of blobs nobody holding it can open.

That is the sealed design the red team asked for (D1 and D2). Everything below is either a
consequence of it or a guard around the link that reaches the page.

## Routes

| Route               | Auth              | What it does                                                       |
| ------------------- | ----------------- | ------------------------------------------------------------------ |
| `GET /vault?t=`     | the signed link   | Renders the password or card form. Consumes nothing                |
| `POST /vault`       | the device cookie | Consumes the link and stages the sealed value                      |
| `GET /cvv?t=`       | the signed link   | One security code, showing brand, last four, total and merchant    |
| `POST /cvv`         | the device cookie | Same, with a shorter time to live                                  |
| `POST /requests`    | the DGX signature | Writes the request row for a link the DGX is about to sign         |
| `POST /inbox/claim` | the DGX signature | Returns and deletes a workspace's unclaimed sealed values          |
| `GET /health`       | none              | `{ ok, configured: { linkKey, sealKey, baseUrl } }`, booleans only |
| `GET /pubkey`       | none              | The sealing public key, so the DGX can check what pages were given |

`verify_jwt = false` in `supabase/config.toml`, and it must be: the caller is a phone browser
following a link that arrived by text and carries no header we chose.

### A GET never consumes a link

iMessage unfurls a link, the relay's preview fetcher unfurls it, and a middlebox in between may
fetch it too, all before a human has touched the screen. A GET that spent the link would hand the
owner a dead link every single time, so rendering is idempotent and free and the single use property
lives entirely on the POST.

A request that is not a browser someone is looking at gets **204 and no body at all**: no page to
cache, no preview image, no Open Graph tags for Apple to keep. Two independent signals, and either
is enough to decline: an `Accept` that does not ask for `text/html`, or a user agent that names
itself a bot. Being wrong in the cautious direction costs a reload, because a GET spends nothing.

### The link is bound to the device that opened it

The first GET sets `fv=<jti>.<32 random bytes>` with `Secure; HttpOnly; SameSite=Strict`, and the
POST requires it. The value carries the `jti` so a cookie set by one link cannot satisfy another,
which matters when the owner has two links open. A SHA-256 of the cookie is recorded on consume, as
evidence for an incident review rather than as a control.

### Every failure is one page

A bad signature, a wrong audience, an expired link, a spent link, a missing row, a workspace that
does not match the signature: all of them render the same sentence with the same status. Nothing
from the token or from the request row is ever echoed into an error.

## The token

Ed25519, `EdDSA`, minted by the DGX and only ever verified here. The DGX holds the private key, so a
compromise of this function's environment can check a link and cannot make one.

Claims, in this byte order (the payload is built by concatenation so the order is a property of the
source, not of a runtime):

```json
{"jti":"…","ws":"…","purpose":"vault","kind":"card","alias":"…","aud":"…","iat":0,"exp":0}
{"jti":"…","ws":"…","purpose":"cvv","purchase_id":"…","aud":"…","iat":0,"exp":0}
```

- `kind` and `alias` appear on a `vault` link only, `purchase_id` on a `cvv` link only.
- `aud` is the **host** of `PUBLIC_BASE_URL`, and it is checked. A token minted for the functions
  URL cannot be replayed against a custom domain, and a dangling `api.risaboss.com` that somebody
  else takes over cannot accept our tokens.
- A vault link may live at most 10 minutes from its own `iat`, a CVV link at most 5. A token whose
  own lifetime exceeds the policy is refused even though it verifies, so a minting bug on the DGX
  cannot hand out a link that is good for a week.

**No merchant, no last four, no total, and no user id in the claims.** The URL travels through the
relay, which sees plaintext. Those facts come from a `fluck_vault_requests` row the DGX writes when
it mints, keyed by `jti`.

## The sealing scheme

ECDH over P-256, HKDF-SHA256, AES-256-GCM. X25519 would be tidier and would give `crypto_box_seal`
compatibility nearly for free, but it is not available in every phone browser that might open one of
these links, and a page that cannot encrypt is a page on which the card is typed and then lost.
P-256 has been in every shipping browser for a decade and mirrors directly onto JCA.

The POSTed `c` field is the standard base64 of:

```
byte    0        version, always 0x01
bytes   1..65    ephemeral P-256 public key, uncompressed X9.62 (0x04 || X32 || Y32)
bytes  66..77    AES-GCM IV, 12 random bytes
bytes  78..      AES-GCM ciphertext with its 16 byte tag appended
```

Derivation, given the recipient public key `R` and a fresh ephemeral pair `(e, E)`:

```
shared  = ECDH(e, R)                      32 bytes, the X coordinate only
key     = HKDF-SHA256(ikm = shared,
                      salt = 32 zero bytes,
                      info = utf8("fluck-vault-v1|" || jti),
                      length = 32)
iv      = 12 random bytes
ct      = AES-256-GCM(key, iv, plaintext, aad = utf8(jti))
```

The `jti` is bound twice, in the HKDF info and in the AEAD associated data, so a blob sealed for one
request cannot be replayed into another even by somebody holding both rows.

The plaintext is compact JSON, and the DGX is its only reader and only validator:

```json
{"kind":"password","username":"…","password":"…"}
{"kind":"card","name":"…","pan":"…","exp":"MM/YY","billing":{"line1":"…","city":"…","postal":"…","country":"…"}}
{"kind":"cvv","cvv":"123"}
```

### Mirroring it on the DGX

`tests/seal.test.ts` implements both halves against this layout and `tests/script.test.ts` decrypts
what the real page script produces, so the description above is executable rather than a claim. In
JCA:

- `KeyPairGenerator.getInstance("EC")` with `ECGenParameterSpec("secp256r1")` for the recipient
  pair. Export the public key as an uncompressed point (`ECPoint` to `0x04 || X || Y`, each
  coordinate left padded to 32 bytes) and base64 it; that string is `FLUCK_SEAL_PUBLIC_KEY`.
- Rebuild the ephemeral point from bytes 1 to 65 into an `ECPublicKey` on the same curve.
- `KeyAgreement.getInstance("ECDH")`, `generateSecret()` gives the 32 byte X coordinate.
- HKDF-SHA256 by RFC 5869 with a 32 byte zero salt and the info string above, 32 bytes out.
- `Cipher.getInstance("AES/GCM/NoPadding")` with a 128 bit tag, the 12 byte IV, and
  `updateAAD(jti.getBytes(UTF_8))`.

## The page

Plain HTML, one inline stylesheet, one inline script, and no third party of any kind. The CSP pins
the script and the style by SHA-256 hash, which is why the script is a constant and takes the
recipient key, the `jti` and the form kind from data attributes on the form rather than having them
interpolated into it.

```
default-src 'none'; script-src 'self' 'sha256-…'; style-src 'sha256-…';
form-action 'self'; frame-ancestors 'none'; base-uri 'none'
```

plus `Cache-Control: no-store`, `Referrer-Policy: no-referrer`, `X-Robots-Tag: noindex`,
`X-Content-Type-Options: nosniff` and HSTS on every response, and `Clear-Site-Data` on the success
page so the back button cannot bring a filled field back onto the screen.

The script validates locally (Luhn on the card number, `MM/YY` on the expiry, three or four digits
on the code), seals, **disables every plaintext input so the browser cannot serialise it**, and
posts the blob and the `jti`. Fields are named `f1` to `f7` rather than `cardnumber`, so nothing
recognises them by name.

The server refuses any body field beyond `c` and `j`, and refuses a `c` that is not a well formed
blob or that looks like a card number. That is a second line of defence, for the case where the
script did not run at all: an old browser, an extension, a CSP mistake of ours. It matters because
Supabase request body logging is platform side and not fully under our control (red team C5).

## The DGX contract

**The DGX holds no Supabase credential.** An earlier draft of this document had it call
`fluck_vault_claim` directly with the project's service role key. That key opens the whole project,
and the box it would sit on also runs a model, so a compromise of the DGX would have become a
compromise of everything rather than of a queue of blobs plus one private key. Instead the DGX
proves itself with the Ed25519 key it already has to hold in order to sign links, and this function
is the only thing in the system with a service role key.

The asymmetry still points the right way: this end can verify a DGX request and cannot forge one,
exactly as it can verify a link and cannot mint one.

### The signature

A detached Ed25519 signature over a canonical string, never over the parsed body, carried in two
headers:

```
X-Fluck-Timestamp: <unix seconds>
X-Fluck-Signature: base64url(Ed25519(privateKey, canonical)), unpadded

canonical = "fluck-vault-signed-v1\n" + METHOD + "\n" + <routed path> + "\n"
          + <unix seconds> + "\n" + <sha256 hex of the raw body>
```

The path is the **routed** path, so a signature cannot be replayed against the other route by moving
the request between the function's three possible mount points. Freshness is a two minute window on
the timestamp and nothing else: there is no nonce table, and neither route needs one. `/requests` is
keyed by a `jti` the DGX chose, so a replay is a primary key conflict rather than a second link, and
`/inbox/claim` deletes what it returns, so a replay collects an empty list.

A bad signature, a stale timestamp and a missing header are all one `401 {"error":"unauthorized"}`.

### Minting a link is two steps, and the row comes first

1. `POST /requests` with `{jti, ws, purpose, kind, alias, expiresAt}` — plus `purchaseId`,
   `merchant`, `brand`, `last4`, `totalCents`, `currency` for a CVV link. `expiresAt` is unix
   seconds and is the token's own expiry; a lifetime longer than the policy for that purpose is
   refused here **and** in `fluck_vault_create`, so a minting bug cannot write a row that outlives
   every token that could reach it. `201` on success, `409` if the id is already taken.
2. Sign the token and text `https://<base>/vault?t=…` or `https://<base>/cvv?t=…`.

### Collecting

`POST /inbox/claim` with `{ws}` returns
`{items: [{id, jti, purpose, kind, alias, purchaseId,
ciphertext, createdAt}]}`, `ciphertext`
base64.

Behind it, `fluck_vault_claim` returns and **deletes** every unclaimed row for that workspace in one
statement, so the value exists in exactly one place at a time: in flight, or in the DGX's memory,
never both. A poller that crashes between the two loses the value, and the owner retypes it. That is
the correct trade for a CVV and it is the point of red team D6: a `SELECT` followed by a `DELETE`
would leave the blob at rest until its TTL.

`ciphertext` comes back as `\x…` hex from PostgREST. Decode it, open it, use it, and let it go.

Poll while a gate is open, and hit `/health` when you open one: it warms the function so a cold
start is not spent inside a five minute CVV window (red team I1).

## Rate limits

Per link: 5 GET and 3 POST. Per address: 20 requests per 10 minutes. On a limit, a generic 429 page
with nothing in it.

**They are in memory, per isolate, and therefore best effort.** The edge runtime may run several
isolates and recycles them, so the counters are neither shared nor durable, and a patient attacker
gets more than those numbers. They stop a stuck retry loop, somebody jabbing refresh and a naive
script. They are not what makes a leaked link safe: the signature, the device cookie, the short
expiry and the single use consume are, and all four hold however many isolates there are. A table
would make them exact at the cost of a round trip on the one path that has to work while somebody is
standing at a checkout. The real limit on abuse belongs where links are **minted**, on the DGX (red
team C6).

## Logging

Route, purpose, the first eight characters of the workspace id, the `jti`, and the outcome. Never a
body, never a claim, never a merchant, never a last four, and never anything typed on the page. A
test asserts it.

## Environment

Set with `supabase secrets set --project-ref pcnwqamqdnsadranufjv …`. `SUPABASE_URL` and
`SUPABASE_SERVICE_ROLE_KEY` are injected by the platform and are not set by hand.

| Variable                | Required | What it is                                                                  |
| ----------------------- | -------- | --------------------------------------------------------------------------- |
| `FLUCK_LINK_PUBLIC_KEY` | yes      | Ed25519 **public** key, 32 raw bytes base64, or a PEM `PUBLIC KEY` block    |
| `FLUCK_SEAL_PUBLIC_KEY` | yes      | P-256 **public** key, uncompressed point (65 bytes, leading `0x04`), base64 |
| `PUBLIC_BASE_URL`       | no       | Defaults to the functions URL below. Its host is the token audience         |

Both are public keys. **Neither private half ever comes near this function or this project**, and a
deployment that put one here would give away the two properties the design is built on.

### The two key pairs the DGX must generate

| Pair         | Algorithm  | Private half                                      | Public half goes to     |
| ------------ | ---------- | ------------------------------------------------- | ----------------------- |
| Link signing | Ed25519    | Signs every `t=` token. DGX only                  | `FLUCK_LINK_PUBLIC_KEY` |
| Sealing      | ECDH P-256 | Opens every sealed blob. DGX only, file mode 0600 | `FLUCK_SEAL_PUBLIC_KEY` |

Keep the sealing private key out of any path the model can read. The plugin's own
`SensitivePathGuard` covers `/var/lib/fluck` and `.boss`, so put it in one of those deliberately
(red team D6).

After deploying, `GET /pubkey` echoes the sealing key the pages are actually being given. Compare it
against what you generated: that is how you learn, without trusting a deploy log, that nobody
swapped the environment variable for a key of their own.

### `PUBLIC_BASE_URL`

Ships unset, on `https://pcnwqamqdnsadranufjv.functions.supabase.co/fluck-vault`. The custom domain
`https://api.risaboss.com` comes later, and until the certificate and CAA records are in place and
there is no dangling CNAME, minting links against it would point owners at a host that may not
resolve and may be somebody else's (red team I3). When it lands, set this and mint with the new host
in `aud`; tokens for the old host stop being accepted, which is the intended behaviour.

## Migration

`supabase/migrations/20260920100000_fluck_vault.sql` creates two tables and three functions, and
`supabase/migrations/20260921100000_fluck_vault_create.sql` adds the fourth, `fluck_vault_create`.
All three functions are `SECURITY DEFINER` with an empty `search_path`, and EXECUTE is revoked from
`anon` and `authenticated` explicitly rather than merely left ungranted, because PUBLIC gets EXECUTE
on a new function by default.

| Object                 | What it is                                                         |
| ---------------------- | ------------------------------------------------------------------ |
| `fluck_vault_requests` | One row per minted link. Non secret display facts only             |
| `fluck_vault_inbox`    | Sealed values waiting to be collected. Ciphertext only             |
| `fluck_vault_describe` | The display facts for one live link. Consumes nothing              |
| `fluck_vault_store`    | Consumes the link and stages the blob, in one transaction          |
| `fluck_vault_create`   | Writes the row for a link the DGX is about to sign                 |
| `fluck_vault_claim`    | Returns and deletes a workspace's unclaimed rows, in one statement |

RLS is on with no policies on both tables, so every role is denied and `service_role` bypasses RLS.
Leaving RLS off would expose them to `anon` through PostgREST.

`fluck_vault_store` takes only a `jti`. Everything the inbox row records about the request is copied
from the request row the DGX wrote, so a token with a swapped `ws` claim cannot stage a value into
another workspace's queue (red team D4).

Both write paths sweep their own expired rows, so neither table can grow without bound on a
deployment nobody remembered to add a cron to.

**Applied and exercised against a throwaway Postgres 16** while this was written: the migration runs
clean, `describe` refuses an expired or consumed link, `store` returns the kind once and NULL on a
replay, the inbox TTLs come out at 15 and 10 minutes, `claim` returns both rows and leaves the table
empty, the purpose and `last4` check constraints reject bad rows, and `anon` is denied both EXECUTE
and SELECT.

## Deployment

```sh
# 1. Apply the migration
supabase db push --project-ref pcnwqamqdnsadranufjv

# 2. Set the two public keys
supabase secrets set --project-ref pcnwqamqdnsadranufjv FLUCK_LINK_PUBLIC_KEY='…'
supabase secrets set --project-ref pcnwqamqdnsadranufjv FLUCK_SEAL_PUBLIC_KEY='…'

# 3. Deploy
supabase functions deploy fluck-vault --project-ref pcnwqamqdnsadranufjv

# 4. Check it
curl -s https://pcnwqamqdnsadranufjv.functions.supabase.co/fluck-vault/health
# {"ok":true,"configured":{"linkKey":true,"sealKey":true,"baseUrl":true}}
curl -s https://pcnwqamqdnsadranufjv.functions.supabase.co/fluck-vault/pubkey
```

## Tests

```sh
cd supabase/functions/fluck-vault
deno task test    # deno test --allow-env --allow-read
deno task check   # deno fmt --check && deno check index.ts tests/*.test.ts
```

73 cases in five files.

| File             | What it covers                                                                            |
| ---------------- | ----------------------------------------------------------------------------------------- |
| `token.test.ts`  | Verification, the exact wire format, expiry, audience, wrong key, `alg` confusion, policy |
| `seal.test.ts`   | The scheme sealed and opened, the byte layout, jti and recipient binding, the blob check  |
| `script.test.ts` | The real inline script run against a fake DOM, decrypted with the recipient private key   |
| `vault.test.ts`  | Routing, non consuming GET, unfurler 204, cookie binding, CSP, replay, plaintext, limits  |
| `signed.test.ts` | The DGX routes: tampered body, wrong key, stale timestamp, moved route, field checks      |

`script.test.ts` exists because the page's script is a **string**, so `deno check` never looks at it
and a typo in it would fail nowhere: the symptom would be a card typed at a checkout that silently
never arrived.
