# Security policy

## Reporting a vulnerability

Report vulnerabilities in this repository, its published files or https://feeds.offseq.com privately, not through
public issues:

- GitHub private vulnerability reporting: [Report a vulnerability](https://github.com/offseq/mirage-feed/security/advisories/new)
- Email `security@offseq.com`
- The CERT.LV coordinated disclosure programme: https://cvd.cert.lv/programs/view/101

Include the affected file or URL, steps to reproduce and the impact you expect. We acknowledge reports within
3 working days.

### Scope

- The generator, safety gates and workflows in this repository.
- Files published under https://feeds.offseq.com/mirage-feed/ and on the `data` branch, including their signatures
  and attestations.
- The https://feeds.offseq.com site (removal form, badges, file delivery).

### Out of scope

- Addresses or indicators you believe are wrongly listed: use the removal process below.
- The Mirage platform at https://mirage.offseq.com and OffSeq's other services, unless the issue reaches this feed.
- Denial of service, volumetric testing, social engineering and findings that need a compromised client.
- Missing security headers or best-practice notes without a demonstrated impact.

### Safe harbour

We will not pursue legal action against good-faith research that stays in scope, avoids privacy violations and
service disruption, and gives us reasonable time to fix the issue before disclosure.

## Listed addresses

To dispute an address in the feed, use https://feeds.offseq.com/removal or write to `abuse@offseq.com`. Removal
requests are not security reports and need no GitHub account.

## Signing key

`SHA256SUMS` is signed with minisign (`SHA256SUMS.minisig`).

- Public key: `RWQeu/vC+HeSo+5whq+ViPiKFUe35GOuuVll6WA6QKlFNirw7IzweToA`
- Key ID: `A39277F8C2FBBB1E`
- Published in this file, in the README and at https://feeds.offseq.com/.well-known/mirage-feed-minisign.pub.
  All three must match.

`SHA256SUMS` also carries a GitHub build-provenance attestation from `.github/workflows/publish.yml` on `main`:

```sh
gh attestation verify SHA256SUMS -R offseq/mirage-feed --signer-workflow offseq/mirage-feed/.github/workflows/publish.yml --source-ref refs/heads/main
```

### Rotation and compromise

- **Planned rotation**: the new public key is published in all three places at least 7 days before it signs its
  first build. For that period each build is signed with the old key and the new key's ID is announced in
  [CHANGELOG.md](CHANGELOG.md).
- **Compromise**: we stop publishing, revoke the key by removing it from all three places, publish a GitHub security
  advisory naming the affected key ID and date range, and resume with a new key. Treat any signature from a revoked
  key as invalid, and rely on the build-provenance attestation to verify files signed in the affected range.
