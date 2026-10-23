# Security policy

## Reporting a vulnerability

Report vulnerabilities in this repository, its published files or https://feeds.offseq.com
privately, not through public issues:

- Email `abuse@offseq.com`
- Or through the CERT.LV coordinated disclosure programme: https://cvd.cert.lv/programs/view/101

Include the affected file or URL, steps to reproduce and the impact you expect. We acknowledge
reports within 3 working days.

## Listed addresses

To dispute an address in the feed, use https://feeds.offseq.com/removal or write to
`abuse@offseq.com`. Removal requests are not security reports and need no GitHub account.

## Verifying releases

`SHA256SUMS` on the `data` branch is signed with minisign (`SHA256SUMS.minisig`) and carries
a GitHub build-provenance attestation. See "Verify a download" in the README.
