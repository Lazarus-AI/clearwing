# Side-Channel Timing Methodology

Timing side-channel attacks exploit measurable differences in the time a system takes to process different inputs. When cryptographic operations, string comparisons, or database lookups take variable time depending on the input, an attacker can extract secret values byte-by-byte by measuring response times across many samples. These attacks are particularly relevant to authentication endpoints, token validation, and password verification where early-exit comparisons or conditional branches leak information.

## Attack Theory

### String Comparison Timing
A naive `==` comparison exits at the first mismatched byte. Comparing "aaaa" against "abcd" returns faster than comparing "abca" against "abcd" because the first fails at byte 1 while the second fails at byte 3. Over many samples, this timing difference (often microseconds) is statistically detectable.

### Hash Computation Timing
HMAC verification that computes the expected hash only for valid users takes longer than an early-exit "user not found" path. Similarly, PBKDF2 computation for valid users with high iteration counts creates measurable timing differences.

### Conditional Branch Timing
If authentication code follows different code paths for valid vs invalid credentials — even with identical final responses — CPU branch prediction, cache effects, and different function calls can create timing signals.

### Network Noise
Real-world timing measurements include network jitter, server load variance, and client-side processing time. Statistical techniques (large sample sizes, outlier rejection, interleaved sampling) are essential to extract signal from noise.

## Detection Methodology

### Step 1: Baseline Timing Profile
```
timing_probe(target, path="/api/v1/auth", method="POST", samples=50, warmup=5)
```
Establishes the response time distribution for the endpoint: mean, median, percentiles, confidence interval, histogram.

### Step 2: Username Enumeration Test
```
timing_compare(
    target,
    path_a="/api/v1/auth", body_a='{"email": "known_valid@example.com"}',
    label_a="valid_user",
    path_b="/api/v1/auth", body_b='{"email": "definitely_fake@example.com"}',
    label_b="invalid_user",
    samples=50, warmup=5
)
```
Interleaved A/B sampling with Welch's t-test. If `significant=True` (p < 0.05), the server processes valid and invalid usernames differently.

### Step 3: SRP-Specific Timing
```
srp_timing_attack(target, username, samples=20, test_type="username")
srp_timing_attack(target, username, samples=20, test_type="proof")
```
Targeted timing comparison for SRP authentication: username lookup timing and M1 proof verification timing.

### Step 4: Full Auth Flow Comparison
```
start_auth_recording("timing_valid")
# ... login with valid credentials ...
stop_auth_recording()

start_auth_recording("timing_invalid")
# ... login with invalid credentials ...
stop_auth_recording()

diff_auth_flows("timing_valid", "timing_invalid")
```
Compare complete authentication flows: per-request timing, crypto operation timing, response body differences.

## Exploitation: Byte-at-a-Time Recovery

When a timing oracle is confirmed, use iterative byte recovery:

### Step 1: Confirm the Oracle
```
timing_compare(
    target,
    body_a='{"token": "a000000000000000"}', label_a="correct_first_byte",
    body_b='{"token": "f000000000000000"}', label_b="wrong_first_byte",
    samples=50
)
```
If the first byte comparison takes longer for the correct value, a byte-at-a-time attack is viable.

### Step 2: Recover Each Byte
```
timing_bitwise_probe(
    target,
    body_template='{"token": "{{PROBE}}"}',
    charset="0123456789abcdef",
    known_prefix="",
    position=0,
    samples_per_candidate=10,
    warmup=3,
    select="max"
)
```
The tool tests each character, ranks by response time, and reports the best candidate with a significance test against the runner-up. Repeat for each position, appending the recovered character to `known_prefix`.

### Step 3: Validate Recovery
After recovering the full token/secret, verify by using it in a legitimate request.

## Statistical Interpretation

| Metric | Meaning | Threshold |
|--------|---------|-----------|
| p-value | Probability of observing this difference by chance | p < 0.05 = significant |
| Cohen's d | Effect size (standardized mean difference) | d > 0.2 small, > 0.5 medium, > 0.8 large |
| 95% CI | Range likely containing the true mean difference | If CI excludes 0, difference is real |
| Outlier rejection | Removes network noise spikes | IQR method (default) or z-score |

### Interpreting Results
- **p < 0.05 AND d > 0.5**: Strong evidence of timing leak — proceed with exploitation
- **p < 0.05 AND d < 0.2**: Statistically significant but tiny effect — may not be exploitable over network
- **p > 0.05**: No evidence of timing leak at this sample size — try increasing samples or reducing network distance

## Network Noise Mitigation

1. **Warmup requests**: First N requests are discarded (default 5) to prime DNS, TCP, TLS caches
2. **Interleaved sampling**: `timing_compare` alternates A-B-A-B requests, canceling linear drift (server load trends, connection pooling effects)
3. **Outlier rejection**: IQR method removes extreme values (network retransmissions, GC pauses). Use `outlier_method="zscore"` for distributions with heavy tails
4. **Sample size**: 50 samples is a reasonable default. For small effects (d < 0.3), increase to 200+
5. **Candidate shuffling**: `timing_bitwise_probe` randomizes candidate order within each round, canceling systematic position-in-sequence bias

## Validation Criteria

- Welch's t-test p-value < 0.05 for the target comparison
- Cohen's d > 0.5 (medium or large effect size)
- 95% confidence interval does not cross zero
- Result is reproducible across multiple independent runs
- Byte-at-a-time recovery produces a valid token/credential

## Known Mitigations

- Use constant-time comparison for all secret-dependent operations (`hmac.compare_digest` in Python, `crypto.timingSafeEqual` in Node.js)
- Ensure uniform code paths for valid and invalid inputs (no early-exit)
- Add artificial fixed-time delays to normalize response times (less effective than constant-time code)
- Implement rate limiting on authentication endpoints
- Use SRP with constant-time M1 verification
- Return identical response structure for valid and invalid credentials
