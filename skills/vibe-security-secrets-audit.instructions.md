---
description: >
  Audits how secrets and sensitive configuration values are stored, transmitted,
  and accessed. Focuses on architectural and contextual patterns that Brakeman and
  Bandit miss: secret sprawl, transmission security, error-channel exposure, and
  runtime secret management practices.
---

# Vibe-Coded Application Security Review — Secrets & Sensitive Configuration Audit

## Purpose

Identify how secrets (API keys, database passwords, encryption keys, OAuth credentials,
webhook signing secrets) and sensitive environment configuration are managed throughout
the application lifecycle: storage, loading, usage, transmission, and disposal.

## Scope Note

Brakeman (Rails) and Bandit (Python) detect some hardcoded credential patterns. This
skill focuses on what they miss: contextual handling patterns, secret sprawl across
a codebase, transmission security, and exposure through secondary channels (errors,
logs, serialization). For all other languages, apply comprehensive enumeration.

---

## Audit Area 1: Hardcoded Secrets

While Brakeman/Bandit catch common patterns, vibe-coded apps introduce hardcoded
secrets in ways that evade regex-based detection. Look for:

### Patterns Brakeman/Bandit Typically Miss

**Secrets in non-obvious variable names:**
```ruby
key = "sk-proj-abcd1234..."          # LLM API key not named 'api_key'
endpoint = "https://hooks.slack.com/services/T.../B.../..."  # Webhook URL with embedded secret
config = { auth: "Bearer eyJhbGciOiJSUzI1NiJ9..." }         # Hardcoded JWT/token
```

**Secrets embedded in connection strings or URLs:**
```python
DATABASE_URL = "postgresql://user:password@host/db"  # Password in URL literal
redis_url = "redis://:mypassword@localhost:6379"
```

**Secrets as default parameter values:**
```python
def connect_to_api(key="sk-prod-realkey123"):  # Default is a real key
    ...
```

**Secrets in test files shipped to production:**
Check if test fixtures, factory files, or spec helpers contain credentials that may
be real (not obviously fake like `password123` or `test_key`). Real-looking keys
(base64-encoded, UUIDs, long hex strings) in test files warrant flagging.

**Secrets in migration files:**
Database migrations sometimes hardcode initial passwords, seed API keys, or embed
encryption keys for data migrations. These are committed to version control permanently.

### Secret Pattern Heuristics

Flag string literals matching any of these patterns in non-test source files:

| Pattern | Likely Secret Type |
|---|---|
| `sk-` followed by alphanumeric | OpenAI / LLM API key |
| `eyJ` (base64 header) | JWT token |
| `ghp_`, `github_pat_` | GitHub personal access token |
| `xox` prefix | Slack token |
| 32–64 char hex strings in assignment context | Generic secret/key |
| `BEGIN RSA PRIVATE KEY` / `BEGIN EC PRIVATE KEY` | Private key |
| Strings matching `https://hooks.slack.com/services/...` | Slack webhook with secret |
| `AKIA` prefix | AWS access key ID |
| `postgres://...:.+@` | Database URL with credentials |

Reference: CWE-798 (Use of Hard-coded Credentials), OWASP A02:2021

Severity: **Critical** for production credentials; **High** for test credentials
that may be real; **Medium** for obviously fake/example values.

---

## Audit Area 2: Environment Variable Handling Architecture

Brakeman/Bandit detect some ENV usage issues. This skill focuses on the architectural
patterns that create systemic risk regardless of individual call sites.

### 2a. Scattered vs. Centralized Access

**Anti-pattern (scattered):** `ENV['SECRET_KEY']` or `os.environ['SECRET_KEY']`
called throughout the codebase in controllers, models, services, and helpers.

**Risk:** No central place to validate secrets exist at startup. Missing secrets
cause runtime failures deep in execution paths, potentially mid-request, with
error messages that may expose the secret name and context. No central place to
apply transformations (e.g., decoding, parsing).

**What to flag:** Count the number of distinct files that directly access environment
variables. If it exceeds 5–10 files, flag as an architectural concern (Info/Low
depending on sensitivity of the secrets accessed).

**Best practice to reference:**
- Rails: centralized in `config/initializers/` or a dedicated `Config` module
- Python: centralized in a `settings.py` / `config.py` with `pydantic-settings`
  or similar, loaded once at startup

### 2b. Missing Presence Validation at Startup

Vibe-coded apps frequently access environment variables without validating they exist
at application startup. This means a missing secret causes a failure at an unpredictable
runtime moment, often with an unhelpful error message.

Look for the absence of startup validation. Specifically:
- Is there an initializer, `on_load`, `startup`, or `lifespan` (FastAPI) hook that
  validates required secrets are present before the app begins serving traffic?
- Does the app use `ENV.fetch('KEY')` (Ruby) or `os.environ['KEY']` (Python, raises
  on missing) vs. `ENV['KEY']` / `os.environ.get('KEY')` (returns nil/None silently)?

Flag the absence of startup validation as **Low/Info** but note the systemic risk.

### 2c. Insecure Default Values

```python
# Dangerous — empty string or known value as fallback secret
secret_key = os.environ.get('SECRET_KEY', '')
secret_key = os.environ.get('SECRET_KEY', 'development-secret-do-not-use')
```

If a default value is provided as a fallback for a security-critical secret
(signing key, encryption key, session secret), flag as **High**. A misconfigured
deployment silently uses the insecure default rather than failing safely.

Reference: CWE-547 (Use of Hard-coded, Security-relevant Constants)

---

## Audit Area 3: Secret Transmission

### 3a. Secrets in URLs / Query Parameters

Secrets in URLs are stored in browser history, server access logs, proxy logs,
and Referer headers. Flag any usage of:
```
GET /api/data?api_key=sk-...
GET /webhook?token=abc123
```
Secrets should be transmitted in request headers (`Authorization`, custom headers)
or request bodies (POST), never in URL query parameters.

Reference: CWE-598 (Sensitive Query String in GET Request), OWASP ASVS v4.0 §9.2.1

Severity: **High**

### 3b. Secrets in HTTP Headers Without TLS

If the application makes outbound calls with secrets in `Authorization` headers,
verify that TLS is enforced (see Audit Area 1, check 4). Also verify that headers
containing secrets are not logged (cross-reference with Audit Area: Logging in
the data exfiltration skill).

### 3c. Secrets Passed to Background Jobs

Cross-reference with the data exfiltration skill's job payload audit. Passing
secrets as job arguments stores them in plaintext in the queue backend.

---

## Audit Area 4: Secrets Exposed Through Error Channels

This is among the most common findings in vibe-coded apps and is consistently missed
by automated tools because it requires understanding what data is in scope.

### 4a. Secrets in Exception Messages

```ruby
rescue => e
  render json: { error: e.message }  # May include secret if exception was about secret
end

# Worse — reflection-based error that includes variable values:
raise "Failed to connect with key #{api_key}: #{e.message}"
```

Look for:
- Exception messages that include string interpolation of variables that may contain
  secrets
- Rescue blocks that surface raw exception messages to API responses
- `inspect` or `to_s` on exception objects rendered to clients

### 4b. Secrets in API Error Responses

Check all error response rendering. Do any error paths return:
- Stack traces (even in "debug" modes that may be enabled in production)?
- Configuration values?
- Environment variable names or values?

Particularly check the application's global exception handler / error middleware,
as vibe-coded apps often add one that is overly verbose.

### 4c. Secrets in Serialized Objects

If an object that contains a secret field (e.g., a `User` model with an `api_token`
field, or a `Config` object with `database_password`) is serialized and sent in an
API response, that secret is exposed.

Look for:
- Serializers or `to_json` / `as_json` methods that do not explicitly exclude
  sensitive fields
- `render json: @user` without a serializer (Rails) — exposes all model attributes
- Pydantic model `model_dump()` or FastAPI `response_model` that includes secret fields

Reference: CWE-312 (Cleartext Storage of Sensitive Information), OWASP A02:2021

---

## Audit Area 5: Version Control Exposure

Secrets in version control are the most severe form of secret exposure because they
persist in git history even after the file is corrected.

### 5a. .env Files and Commit History

- Is `.env` in `.gitignore`? Check `.gitignore` explicitly.
- Is a `.env.example` or `.env.sample` file present? If so, does it contain
  real-looking values (as opposed to clearly placeholder values)?
- Check for `config/secrets.yml`, `config/credentials.yml` (unencrypted), or
  `config/database.yml` with hardcoded passwords.
- Python: check `settings.py`, `local_settings.py`, `config.py` for committed secrets.

**Note to reviewer:** If you have access to git history, check `git log --all -S 'SECRET'`
for secrets that may have been committed and removed. Flag this as a recommended
manual step if git history is accessible.

### 5b. CI/CD Configuration Files

Check `.github/workflows/`, `.gitlab-ci.yml`, `Jenkinsfile`, `.circleci/config.yml` for:
- Hardcoded secrets in environment variable definitions
- Secrets echoed in script steps (`echo $SECRET`)
- Artifact uploads that might include `.env` files

Reference: CWE-321 (Use of Hard-coded Cryptographic Key)

---

## Audit Area 6: Runtime Secret Management

### 6a. Secret Rotation Support

Can secrets be rotated without a code change or deployment? Flag applications where:
- Secrets are read only at startup and cached in memory (rotation requires restart)
- There is no mechanism to invalidate previously-issued tokens if a signing key is rotated

Flag as **Info/Low** but note the operational risk during a breach response.

### 6b. Encryption Key Management

If the application encrypts data at rest, locate the encryption key and evaluate:
- Is the key stored separately from the encrypted data?
- Rails: `config/credentials.yml.enc` protects keys, but the master key must not
  be committed. Verify `config/master.key` is in `.gitignore`.
- Is the same key used for all data, or are there separate keys per data type / tenant?
- Is there a mechanism to re-encrypt data if a key is compromised?

### 6c. Session Secret Strength

- Rails: verify `secret_key_base` is not a short, predictable string.
- Python/Flask: verify `SECRET_KEY` is sufficiently random (≥ 32 bytes from a CSPRNG).
- Flag any session secret that looks like it was typed manually rather than generated.

---

## Output Instructions

For each finding, use the standard schema from `vibe-security-entrypoint`.
Use category tag: `SECRETS`.

After individual findings, append a **Secret Inventory** section:

```
## Secret Inventory

| Secret Name | Storage Location | Access Pattern | Transmitted Where | Risk Assessment |
|-------------|-----------------|----------------|------------------|-----------------|
| DATABASE_URL | ENV var | Scattered (8 files) | Never | Medium — no central validation |
| STRIPE_SECRET | ENV var | Centralized | HTTPS POST to Stripe | Low — correct usage |
| SENDGRID_KEY | Hardcoded in mailer.rb:14 | N/A | Outbound email | Critical — hardcoded |
| ...         | ...             | ...            | ...              | ...             |
```
