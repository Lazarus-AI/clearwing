# CVE Research

Systematic vulnerability research using the local CVE database. Covers
searching for known vulnerabilities by product, protocol, or weakness class,
and cross-referencing findings with the knowledge graph.

## Methodology

### Step 1: Initialize the Database

If the CVE database has not been set up, update it first:

```
cve_db_update(zip_path="/path/to/cvelistV5-main.zip")
```

Or download from GitHub (requires network access, ~550 MB):

```
cve_db_update()
```

The database contains 300k+ CVEs with full-text search via FTS5.

### Step 2: Product-Specific Search

Search for CVEs affecting the target product or vendor:

```
cve_search(query="1password OR agilebits", max_results=25)
```

For broader searches, use OR syntax:

```
cve_search(query="password manager vault encryption", min_cvss=7.0)
```

### Step 3: Protocol and Algorithm Search

Search for CVEs affecting cryptographic protocols and algorithms used by
the target:

```
cve_search(query="SRP authentication bypass")
cve_search(query="PBKDF2 side channel")
cve_search(query="AES-GCM nonce reuse")
cve_search(query="WebCrypto")
```

### Step 4: Weakness Class Search

Search by CWE to find similar vulnerability patterns:

```
cve_search(query="authentication bypass", cwe="CWE-287")
cve_search(query="timing side channel", cwe="CWE-208")
cve_search(query="nonce reuse", cwe="CWE-323")
```

### Step 5: Deep Dive

For any CVE that looks relevant, get the full record:

```
cve_lookup(cve_id="CVE-2022-32550")
```

### Step 6: Cross-Reference

Store relevant CVEs in the knowledge graph for later reference:

```
store_knowledge(key="cve:CVE-2022-32550", value="SRP connection validation
deviation in 1Password — server impersonation possible")
```

## Search Tips

- Use quotes for exact phrases: `"nonce reuse"`
- Use OR for alternatives: `"1password" OR "agilebits"`
- Filter by severity: `min_cvss=7.0` for high/critical only
- Filter by date: `date_after="2023-01-01"` for recent CVEs
- Filter by CWE: `cwe="CWE-287"` for authentication bypass

## Common CWE IDs for Crypto Research

| CWE | Description |
|-----|-------------|
| CWE-208 | Observable Timing Discrepancy |
| CWE-287 | Improper Authentication |
| CWE-295 | Improper Certificate Validation |
| CWE-323 | Reusing a Nonce, Key Pair in Encryption |
| CWE-326 | Inadequate Encryption Strength |
| CWE-327 | Use of a Broken or Risky Cryptographic Algorithm |
| CWE-328 | Use of Weak Hash |
| CWE-330 | Use of Insufficiently Random Values |
| CWE-347 | Improper Verification of Cryptographic Signature |
| CWE-916 | Use of Password Hash With Insufficient Computational Effort |
