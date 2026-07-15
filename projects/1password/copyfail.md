# Copy Fail (CVE-2026-31431)

Disclosed 2026-04-29 by Xint Code / Theori. AI-assisted discovery.

## Summary

Logic bug in Linux kernel's `authencesn` crypto template. Unprivileged local user gets a controlled 4-byte write into the page cache of any readable file. 732-byte Python PoC roots Ubuntu, Amazon Linux, RHEL, SUSE. Affects all kernels since 2017 (commit 72548b093ee3).

## Mechanism

Three components intersect:

1. **AF_ALG socket** exposes kernel crypto to unprivileged userspace
2. **splice()** delivers page cache pages by reference into crypto scatterlists (no copy)
3. **algif_aead in-place optimization** (2017) sets `req->src = req->dst`, chaining page cache tag pages into the writable destination scatterlist via `sg_chain()`

`authencesn` (IPsec ESN support) uses the destination buffer as scratch space for ESN byte rearrangement. It writes 4 bytes at `dst[assoclen + cryptlen]` — past the output boundary, into the chained page cache pages. The write value comes from AAD bytes 4-7 (attacker-controlled). The target offset is controlled via splice offset, splice length, and assoclen.

The HMAC check fails (ciphertext is fabricated), recvmsg returns an error, but the page cache write persists. The corrupted page is never marked dirty, so on-disk checksums see nothing.

## Exploit

```
AF_ALG socket -> bind authencesn(hmac(sha256),cbc(aes))
  -> sendmsg (AAD bytes 4-7 = payload chunk) + splice (target file pages)
  -> recv triggers decrypt -> 4-byte write to page cache
  -> repeat for each chunk of shellcode
  -> execve("/usr/bin/su") loads corrupted setuid binary from page cache
  -> root
```

Attacker controls: which file, which offset, which 4-byte value. No race, no retry, no crash.

## Stealth

Page cache corruption without dirty-page marking. dm-verity, AIDE, `rpm -V` all compare on-disk content and see nothing. Only the in-memory page cache is modified. Persists until page eviction.

## Cross-container

Page cache is shared across all processes on a host, including across container namespaces. This is a container escape primitive. Part 2 (Kubernetes escape) forthcoming.

## Mitigation

- Patch kernel (fix: commit a664bf3d603d, reverts to out-of-place operation)
- Or block AF_ALG: `echo "install algif_aead /bin/false" > /etc/modprobe.d/disable-algif-aead.conf`

## Relevance to 1Password CTF

Indirect. If we find application-level RCE on bugbounty-ctf.1password.com, this could escalate from container to host (if unpatched — disclosure is today, 2026-04-29). But the CTF challenge is cryptographic (access a Secure Note behind 2SKD), so this is a potential escalation path, not an entry point. Worth revisiting if we get code execution.

## Source

Xint Code blog, 2026-04-29. AI-assisted discovery: human identified attack surface (AF_ALG + splice page cache provenance), Xint Code traced all reachable codepaths in crypto/ subsystem.
