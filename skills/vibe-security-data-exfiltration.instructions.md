---
description: >
  Maps all paths through which data exits the application boundary. Focuses on what
  automated SAST tools miss: logic-level data flows, third-party SDK transmission,
  logging as an exfiltration vector, and export endpoints with inadequate scoping.
---

# Vibe-Coded Application Security Review — Data Exfiltration Audit

## Purpose

Identify every path through which data — especially user data, PII, and sensitive
business data — can leave the application boundary. This includes intentional paths
(API calls, file exports) and unintentional ones (logging, error reporting, SDKs).

## Scope Note

Brakeman and Bandit do not analyze the *content* of outbound data or the
business-logic appropriateness of what is sent where. This skill focuses on exactly
that gap. For all other languages (not Ruby/Rails or Python), additionally apply
standard SAST-level checks since equivalent pipeline tooling is not assumed.

---

## Audit Area 1: Outbound HTTP/HTTPS Calls

Locate all HTTP client usage across the codebase using these library signatures:

| Language | Libraries to Locate |
|---|---|
| Ruby | `Net::HTTP`, `HTTParty`, `Faraday`, `RestClient`, `Excon`, `Typhoeus`, `http` gem |
| Python | `requests`, `httpx`, `urllib`, `urllib3`, `aiohttp`, `httplib2`, `boto3` (HTTP endpoints) |
| Node.js | `fetch`, `axios`, `node-fetch`, `got`, `superagent`, `http.request` |
| Go | `http.Get`, `http.Post`, `http.NewRequest`, `resty` |
| Java | `HttpClient`, `RestTemplate`, `OkHttp`, `Feign` |

For **each HTTP client call** found, answer all of the following:

**1. What data is being sent?**
Trace the origin of every variable included in the request URL, query parameters,
headers, and body. Follow the data backward to its source. Ask: can this variable
contain user PII, session data, authentication material, or confidential business data?

**2. Is more data sent than intended?**
Vibe-coded apps commonly serialize entire model objects into API payloads when only a
subset of fields is needed. Flag any serialization of ActiveRecord models, SQLAlchemy
models, Pydantic models, or ORM objects into outbound requests without explicit field
selection.

**3. Is the destination URL static or dynamic?**
If the URL is constructed from user input, a database value, or any runtime variable
that a user can influence, flag it as a **Server-Side Request Forgery (SSRF)** risk.
(CWE-918, OWASP A10:2021)

Severity: **Critical** if user controls the URL host or scheme; **High** if user
controls path or parameters that could redirect to internal services.

**4. Are TLS/SSL errors suppressed?**
Flag any calls that disable certificate verification:
- Ruby: `verify_mode: OpenSSL::SSL::VERIFY_NONE`
- Python: `verify=False` in requests/httpx
- Node: `rejectUnauthorized: false`

These are High severity in production code. (CWE-295)

---

## Audit Area 2: Logging as an Exfiltration Vector

Logs frequently ship to external aggregation systems (Splunk, Datadog, CloudWatch,
Elastic/ELK). A logging statement is functionally equivalent to sending data to those
systems. This is consistently missed by automated SAST tools.

### What to Look For

**Middleware / filter-level request logging:**
Many vibe-coded apps add logging at the middleware level that captures entire request
and response bodies. Locate any `before_action`, middleware class, or filter that logs
`request.body`, `params`, `response.body`, or equivalent. These almost always capture
passwords, tokens, and PII from form submissions and API calls.

**Exception handlers logging full context:**
Locate rescue/except/catch blocks. If they log `exception`, `e`, or `error` with
`inspect`, `to_s`, or full string formatting, check what local variables are in scope
at that point — they are frequently included in the exception message or context.

**ORM / query logging in production:**
Some frameworks log SQL queries with bound parameters in debug mode. Verify that
production logging levels suppress query-level logging, especially for queries
involving password hashes, tokens, or PII columns.

**Specific patterns to flag:**
```
# Ruby — logs full params hash including passwords
Rails.logger.info "Processing request: #{params.inspect}"

# Python — logs entire request context
logging.debug(f"Request data: {request.json()}")

# Any language — structured log with over-broad field capture
logger.info("user_action", user=user.__dict__)
```

Reference: CWE-532 (Insertion of Sensitive Information into Log File)
Severity: **High** if PII or credentials confirmed; **Medium** if probable given
typical usage patterns.

---

## Audit Area 3: Third-Party Analytics, Error Reporting, and Telemetry SDKs

These SDKs are legitimate integrations that silently exfiltrate application data to
third-party services. Review each one found for scope creep and data minimization
violations.

### SDK Categories and Specific Checks

**Error Reporting:** `Sentry`, `Bugsnag`, `Rollbar`, `Airbrake`, `Honeybadger`
- Is `send_default_pii` (Sentry) or equivalent enabled? This sends IP addresses,
  user agents, cookies, and request bodies automatically.
- Are custom `set_user()` or `identify()` calls attaching more user fields than
  necessary (e.g., full user object vs. just an anonymous ID)?
- Is local variable capture enabled? (Sentry: `include_local_variables`,
  Bugsnag: `send_code`) This can expose secrets that exist as local variables
  at the point of an exception.
- Are data scrubbing rules (`before_send` hooks, `denylist` patterns) configured
  to redact sensitive fields?

**APM / Performance Monitoring:** `Datadog`, `New Relic`, `AppSignal`, `Scout`
- Are custom spans or traces attaching raw user data, query parameters, or
  request bodies as metadata?
- Is distributed tracing propagating user-identifying headers across service
  boundaries to services that should not have that information?

**Analytics:** `Mixpanel`, `Amplitude`, `Segment`, `Heap`, `Rudderstack`
- Are server-side analytics events attaching PII to event properties?
  (e.g., `track("order_placed", {user_email: user.email, items: cart.items})`)
- Is a user identity (`identify()`) call linking anonymous analytics data to
  PII fields that should not be in the analytics system?

**Payment Processors:** `Stripe`, `Braintree`, `PayPal`
- Verify that raw card numbers never touch the server (they should go directly
  to the processor's JS SDK). If any route receives card numbers as parameters,
  flag as **Critical**. (PCI-DSS SAQ A compliance)

Reference: OWASP ASVS v4.0 §13.2.6
Severity: **High** if PII or credentials confirmed in SDK data; **Medium** if
excessive scope without confirmed sensitive data.

---

## Audit Area 4: Message Queue and Background Job Payloads

Job arguments are serialized and stored in the queue (Redis, database, SQS) in
plaintext. They are also frequently included in job failure logs and retry records.

**Locate:** `Sidekiq`, `Resque`, `Delayed::Job`, `GoodJob`, `Celery`, `RQ`,
`Dramatiq`, `SQS`, `RabbitMQ`, `Kafka`, `Redis Pub/Sub`

**For each job class found, check:**

1. **What is passed as arguments?** The correct pattern is to pass only resource IDs
   and look up the object inside the job. Flag any job that accepts raw PII, auth
   tokens, or secrets as arguments:
   ```ruby
   # Bad — token stored in queue plaintext
   UserSyncJob.perform_later(user_id, api_token)

   # Good — token fetched from secure store inside job
   UserSyncJob.perform_later(user_id)
   ```

2. **Are job failure records exposed?** When jobs fail, full argument payloads are
   often visible in the queue UI (Sidekiq Web, Flower for Celery). Confirm that
   queue UIs are protected by authentication.

3. **Are jobs publishing events to message brokers?** Check the payload of any
   `publish`, `produce`, or `send_message` call. Apply the same data minimization
   analysis as for outbound HTTP calls.

Severity: **High** if auth tokens or PII confirmed in job args; **Medium** if full
model objects are serialized where IDs would suffice.

---

## Audit Area 5: File System Writes and Object Storage

**Locate all file write operations:**
- Ruby: `File.write`, `IO.write`, `File.open(..., 'w')`, `CSV.open`
- Python: `open(..., 'w')`, `pathlib.Path.write_text`, `csv.writer`
- Cloud storage SDKs: `ActiveStorage`, `Carrierwave`, `Shrine` (Ruby);
  `boto3 S3`, `azure-storage-blob`, `google-cloud-storage` (Python)

**For each file write, check:**

1. **What data is written?** Trace variable origins. Flag writes of PII, auth
   material, or bulk user data.

2. **Are temporary files cleaned up?** Look for `Tempfile`, `tempfile.NamedTemporaryFile`,
   `tmp/` directory writes. Confirm cleanup happens in `ensure`/`finally` blocks
   rather than relying on garbage collection.

3. **Cloud storage permissions:** Are uploaded objects private by default? Flag any
   `public_read` ACL or equivalent. Are presigned URL expiry times reasonable
   (not weeks or months)?

4. **Path traversal in filenames:** If a filename is user-controlled, can path
   traversal characters (`../`) cause writes outside the intended directory?
   (CWE-22) Note: Brakeman/Bandit may catch some of these; include if the
   pattern is not straightforwardly detectable.

---

## Audit Area 6: Export and Download Endpoints

Bulk data export endpoints are a high-value target: even a legitimately authenticated
user can use them for large-scale data theft if they are not properly scoped.

**Locate endpoints that produce:** CSV downloads, Excel exports, PDF generation,
JSON bulk APIs, data portability / "download your data" features, report generation.

**For each export endpoint, verify:**

1. **Is the export scoped to the requesting user's data?** The most common flaw is
   an export that accepts a parameter (date range, user group, account ID) and
   queries the database without filtering by the current user's ownership.
   Example: `GET /reports/export?account_id=123` — can a user substitute any
   account ID?

2. **Is there rate limiting?** Even authorized exports can be abused for systematic
   data harvesting if unlimited requests are allowed. Flag any export endpoint with
   no rate limiting or throttling. (OWASP ASVS v4.0 §13.1.1)

3. **Do exports bypass field-level access controls?** It is common for the normal
   API to omit sensitive fields while the CSV export includes them all because the
   serializer was not applied to the export path.

4. **Are exports audited?** Bulk export events should be logged with the requesting
   user identity and the scope of the export for forensic purposes.

---

## Audit Area 7: Real-Time Channels (WebSocket / SSE / ActionCable)

**Locate:** ActionCable channels, Socket.io handlers, FastAPI WebSocket routes,
Django Channels consumers, Server-Sent Event (SSE) endpoints.

**For each channel or SSE endpoint:**

1. **What data is broadcast?** Is the broadcast scoped to a specific user/room/tenant,
   or is it a global broadcast that all connected clients receive?

2. **Is subscription authenticated and authorized?** Vibe-coded apps commonly add
   real-time features with minimal auth. Check: is the WebSocket handshake
   authenticated? Is each subscription verified against the user's permissions?

3. **Can channel parameters be manipulated?** Example: `App.cable.subscriptions.create({channel: "RoomChannel", room_id: 42})` — can a user substitute any `room_id`
   and receive that room's messages? This is an IDOR variant specific to real-time channels.

---

## Audit Area 8: Email and Messaging Service Integrations

**Locate:** `ActionMailer`, `SendGrid`, `Mailgun`, `Postmark`, `smtplib`, `sendgrid-python`,
`Twilio` (SMS), `SNS`, `Slack API`, `Teams webhooks`.

**Check:**
1. **What data appears in email/SMS bodies?** Flag PII or sensitive data included
   beyond what is necessary for the message purpose.
2. **Is the recipient address user-controlled?** If a user can specify where
   notifications are sent, they could redirect security alerts or data exports.
   (Example: "notify me at this email" with no validation.)
3. **Are webhook URLs validated?** Outbound webhooks to user-supplied URLs are an
   SSRF vector and a data exfiltration path simultaneously.

---

## Output Instructions

For each finding, use the standard schema from `vibe-security-entrypoint`.
Use category tag: `DATA-EXFIL`.

After all individual findings, append a **Data Flow Map** section to the report:

```
## Data Flow Map

| Destination | Data Transmitted | User-Controlled Destination? | Scoped to User? | Risk |
|-------------|-----------------|------------------------------|-----------------|------|
| Sentry      | Exception ctx + user email | No | Partial | Review SDK config |
| Sidekiq     | user_id, api_token in args | No | N/A | High — token in queue |
| S3 bucket   | CSV export of all users | No | No | High — missing scope |
| ...         | ...             | ...                          | ...             | ...  |
```

This map gives reviewers and developers a holistic view of the application's data
egress surface, independent of individual findings.
