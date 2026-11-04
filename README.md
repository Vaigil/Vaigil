# Signed miss-rate scorecards

This branch is a publication, not a development branch: one datestamped
scorecard per weekly run of the shipped wind-tunnel corpus, each one
dual-signed (Ed25519 and ML-DSA-65) in the context
`aertun/windtunnel-scorecard/v1`. Nothing here is ever rewritten — a
correction is a new card, and the history is the point: a signed weekly
record cannot be backdated, and every week un-run is a week nobody can
add later.

Every card is the full shipped scenario corpus (`windtunnel-seed-v1`)
run in reference mode — this project's own detection pack as the
calibrated instrument — over the shipped base stream (`wt-baseline-v1`)
at seed 7. The card names all of that, with digests, before it names a
single number, because a number without those names is a claim rather
than a measurement.

## Verify a card offline

You need three things: the binary, this branch's `public-key.json`, and
the card. No network after the downloads, no account, no vendor's cloud.

1. Get the binary. Either download a release artefact from the main
   repository's releases, or build it from source — the standard library
   is the only dependency:

   ```
   git clone -b scorecards https://github.com/aertun/aertun.git cards
   cd cards
   git clone https://github.com/aertun/aertun.git src
   cd src && go build -o ../bin/apv ./cmd/aertun
   ```

   (Or use any `apv` binary you already have; the verify path is
   offline and stable across releases of the same schema.)

2. Verify with the public key, nothing else:

   ```
   bin/apv windtunnel verify --key public-key.json scorecard-2026-11-04.json
   ```

   Expected output, exit code 0:

   ```
   verified: both signatures hold, in context aertun/windtunnel-scorecard/v1, by key 2c687842b4011038; document sha256 2e4ea1848643…
   ```

A tampered card refuses with the reason: an edited document fails its
own digest check first ("it has been edited since it was written, and
nothing rendered from it can be cited"), a card from another schema is
refused by name, and a signature that does not hold names which half
failed. Verify never takes a key from the document itself — trusting
the document to supply its own verifier would be the forgery the
command exists to refuse.

To read a verified card in words:

```
bin/apv windtunnel scorecard scorecard-2026-11-04.json
```

## What the verification actually checks

- **The self-digest.** The document carries a SHA-256 over its own
  canonical form; any edit anywhere breaks it, before signatures are
  even consulted.
- **Both signatures.** Ed25519 and ML-DSA-65 over the digest, both
  required, both in the wind tunnel's own context string — so this
  signature can never be re-presented as a content-pack signature or an
  audit-log head, because the context is inside the signed bytes.
- **The key id.** The card names the key that signed it
  (`2c687842b4011038`); the verifier checks that the trusted public
  key is that key.

## The key, honestly

`public-key.json` is the public half of a dedicated CI signing key. Its
private half lives only in a repository secret
(`SCORECARD_SIGNING_KEY`) used by the weekly workflow; it is not, and
has never been, the content-plane root key or any store's release key —
the content plane's trust split (offline root, online release) is a
separate ceremony for signed detection packs, and a scorecard key that
could also sign packs is a key doing two jobs.

If the key ever rotates, `public-key.json` here and the committed seed
pair on `main` (`scorecards/public-key.json` with the genesis card)
change together in one open commit, and the old key's cards keep
verifying against the key file that is committed beside them in the
history. The key id on every card tells you which key to trust for it.

## What a card claims, and what it does not

- **It claims what ran.** Corpus, base stream, reference pack, seed,
  engine version — each with a digest. That is the anti-gaming
  mechanism: you can check that the scenario list is the whole pinned
  corpus, not a flattering subset.
- **It claims a miss rate with its interval, not a point.** The first
  card: 0 of 4 must-alert scenarios missed, 95% Wilson interval 0.0% to
  49.0%. Four must-alert scenarios is a wide opinion, and it is
  published as one. Read the interval, always.
- **It names its blind spots.** Each scenario's declared blind spot is
  restated on the card, and the two telemetry-only outcomes (the
  scenarios the current pack honestly cannot alert on) are reported as
  the gaps they are, not quietly scored as catches.
- **It does not claim when, beyond the signature.** `generated_at` is
  signed, but nothing yet anchors it to an external clock. The
  project's OpenTimestamps anchoring exists for the audit log; its CLI
  commits a store's log head, not an arbitrary scorecard digest, and
  wiring scorecard digests to OpenTimestamps or a SCITT transparency
  receipt (RFC 9943/9942) is planned phase-2 work rather than something
  forced in here. Until then: a card proves **what** ran and that the
  key signed it; **when** rests on this branch's public commit
  history.

## Reproduce a run

Same build, same corpus, same seed, same numbers — the rows are
deterministic; only the timestamp and the scratch directory name move:

```
bin/apv windtunnel run --score reference --seed 7 \
  --key YOUR-KEY-FILE --public-key YOUR-PUBLIC-KEY.json \
  --out your-scorecard.json
```

An unsigned card of your own says so itself and makes no claim a
signature would back. The scratch spools a run writes are ephemeral
(temporary directories) and are the one artifact of a run that holds
stream data — everything published here is digests and counts.

## The schedule

The weekly run and its publication are defined in
`.github/workflows/scorecard.yml` on `main`: Mondays at 06:23 UTC, plus
a manual dispatch. The workflow verifies its own output before it
publishes, and verifies the pushed branch bytes after — the same
command a stranger runs above.
