---
description: >
  Identifies privilege escalation paths in applications where AuthN/AuthZ is
  handled by an upstream system. Focuses on mass assignment, IDOR, parameter
  tampering, authorization coverage gaps, and business logic flaws — the
  categories most commonly missed by automated tools and most prevalent in
  vibe-coded applications.
---

# Vibe-Coded Application Security Review — Privilege Escalation Audit

## Purpose

Identify all paths through which an authenticated user can access resources,
perform actions, or assume roles beyond their intended authorization. This audit
assumes that authentication (verifying identity) and coarse-grained authorization
(verifying the user is logged in and has a base role) happen upstream. The focus
is on fine-grained authorization failures within the application itself.

## Context: Why Vibe-Coded Apps Are Especially Vulnerable

LLM-generated code prioritizes making features work. Authorization is a
cross-cutting concern that requires understanding the data model, user roles, and
business rules — context that an LLM has only partially at any given generation
step. The result is code that works functionally for the "happy path" but leaves
authorization gaps at edge cases, secondary endpoints, background jobs, and
less-trafficked features.

OWASP A01:2021 (Broken Access Control) has been the #1 web application risk
category for multiple consecutive years. It encompasses all findings in this skill.

## Scope Note

Brakeman detects `permit!` (mass assignment) and some unsafe redirect patterns.
Bandit does not address authorization logic. This skill focuses on the authorization
issues that require semantic understanding of the application's data model and user
roles — issues no static analysis tool currently catches reliably.

---

## Audit Area 1: Insecure Direct Object Reference (IDOR)

IDOR is the most common Critical/High finding in web applications and is
almost entirely undetectable by automated tools.

**The core question for every resource lookup:**
Is the object fetched by ID *scoped to the current user's access*, or is it
a raw lookup that any authenticated user can satisfy by knowing (or guessing)
the ID?

### How to Identify IDOR Systematically

For every controller action, API endpoint, or route handler that accepts an
ID parameter (`:id`, `user_id`, `order_id`, `document_id`, etc.), find the
corresponding database query and ask:

**Vulnerable pattern:**
```ruby
# Any authenticated user can access any order by changing the ID
def show
  @order = Order.find(params[:id])
end
```

**Correct pattern:**
```ruby
# Order is scoped to the current user — another user's ID returns 404
def show
  @order = current_user.orders.find(params[:id])
end
```

**Python equivalent (FastAPI/SQLAlchemy):**
```python
# Vulnerable
order = db.query(Order).filter(Order.id == order_id).first()

# Correct
order = db.query(Order).filter(Order.id == order_id, Order.user_id == current_user.id).first()
```

### IDOR in Nested Resources

Pay particular attention to nested routes and nested resource lookups. Vibe-coded
apps commonly scope the parent but not the child:

```ruby
# routes.rb: resources :projects do resources :tasks end
def show
  @project = current_user.projects.find(params[:project_id])  # Scoped ✓
  @task = Task.find(params[:id])  # NOT scoped — IDOR on tasks ✗
end
```

### IDOR in Bulk / Filter Operations

Endpoints that accept a list of IDs for batch operations are particularly prone:
```
DELETE /api/messages?ids[]=1&ids[]=2&ids[]=3
```
Verify that every ID in the array is validated against the current user's ownership,
not just that the user is authenticated.

### IDOR in Background Jobs

If a background job operates on a resource ID passed as an argument, verify the job
re-validates authorization at execution time. The job may execute in a different
context than the request that enqueued it, and the user's permissions may have
changed (or the job may be enqueued by an admin on behalf of a user, inadvertently
granting job-level access).

Reference: CWE-639 (Authorization Bypass Through User-Controlled Key), OWASP A01:2021

Severity: **Critical** if the resource contains PII or sensitive data; **High** if
it allows action on another user's non-sensitive data; **Medium** if IDs are
non-sequential (UUIDs) making guessing difficult but enumeration still possible.

---

## Audit Area 2: Mass Assignment

Brakeman detects `permit!` in Rails. This skill extends the analysis to subtler
patterns and other frameworks.

### Rails — Beyond permit!

```ruby
# Brakeman catches this:
@user.update(params[:user].permit!)

# Brakeman may miss these:
@user.assign_attributes(user_params)  # Check what user_params permits
@user.update(role: params[:role])     # Explicit assignment from params — check if role should be user-settable
User.create(params[:user])            # No strong params at all

# Also check: does strong_parameters permit fields that should not be user-settable?
def user_params
  params.require(:user).permit(:name, :email, :role, :admin, :account_id)
  #                                              ^^^^   ^^^^^   ^^^^^^^^^^
  #                                              Should these be user-settable?
end
```

**What to look for in permitted parameter lists:**
- `role`, `admin`, `is_admin`, `is_staff`, `permissions` — role/privilege fields
- `user_id`, `account_id`, `organization_id` — ownership/tenancy fields
- `approved`, `verified`, `confirmed`, `status` — state machine fields that should
  only be changed through defined transitions
- `price`, `amount`, `discount`, `credits` — financial fields

### Python / Django / SQLAlchemy — Mass Assignment Equivalents

Django:
```python
# Vulnerable — accepts any field from POST data including is_staff, is_superuser
user = User(**request.POST.dict())
form = UserForm(request.POST, instance=user)  # Check Meta.fields in UserForm
```

Pydantic / FastAPI:
```python
# Check what fields the input schema exposes vs. what the model has
class UserUpdate(BaseModel):
    name: str
    email: str
    role: str        # Should this be in the update schema?
    account_id: int  # Should this be in the update schema?
```

SQLAlchemy:
```python
# Vulnerable — updates any key from untrusted dict
for key, value in request.json.items():
    setattr(user, key, value)
```

Reference: CWE-915 (Improperly Controlled Modification of Dynamically-Determined Object Attributes), OWASP A01:2021

Severity: **Critical** if role/admin fields are exposed; **High** if ownership fields
are exposed; **Medium** for other business-sensitive fields.

---

## Audit Area 3: Parameter Tampering

Beyond mass assignment, look for individual parameter values from user input that
influence access control decisions.

### User-Controlled Authorization Context

```
POST /api/create_report
{ "user_id": 999, "account_id": 42, "type": "full_export" }
```

If `user_id` or `account_id` is accepted from the request body and used to determine
what data to operate on — rather than derived from the authenticated session — any
user can supply any value.

**Look for:**
- Queries or operations that use a `user_id`, `account_id`, or `organization_id`
  read from request parameters rather than from the session/JWT
- `current_user_id = params[:user_id]` or `account = Account.find(request.json['account_id'])`
  without verifying the current user has access to that account

### Role / Permission Fields in Request Parameters

```
POST /api/users { "email": "...", "role": "admin" }
GET /api/admin/dashboard?admin=true
```

Flag any route where a role, permission level, or boolean admin flag is accepted as
a request parameter and trusted without verification.

### Price and Quantity Manipulation

In any e-commerce, billing, or credit system:
```
POST /api/checkout { "items": [...], "total": 0.01 }
POST /api/purchase { "plan": "enterprise", "price": 9.99 }
```

Verify that prices, totals, and financial values are always computed server-side
from canonical data (product catalog, pricing rules) rather than accepted from
client-supplied parameters. This is consistently generated incorrectly by LLMs.

Reference: CWE-472 (External Control of Assumed-Immutable Web Parameter)

---

## Audit Area 4: Authorization Coverage — Unchecked Routes and Actions

Vibe-coded apps often have authorization checks on the primary CRUD actions but
miss secondary, administrative, or batch actions.

### Systematic Route Coverage Check

For the complete list of routes/endpoints, verify each one has an explicit
authorization check. Create a mental (or literal) matrix:

| Route | Auth Check Present? | What Does It Check? | Gap? |
|-------|---------------------|---------------------|------|
| GET /orders/:id | Yes — current_user.orders | Ownership | None |
| POST /orders/:id/cancel | Yes — before_action | ? | Verify scope |
| GET /orders/export | No | N/A | **Missing — IDOR risk** |
| DELETE /orders/batch | No | N/A | **Missing** |

### Admin / Internal Route Exposure

Locate all admin, internal, debug, or management routes:
- Rails: `namespace :admin`, routes under `/admin/`, `mount` calls for admin engines
- Python: routes prefixed `/admin/`, `/internal/`, `/debug/`
- Any route referencing "management", "dashboard", "console", "ops"

Verify that each admin route has an explicit authorization check that validates
the admin role — not just authentication. Common failure: admin routes check
`authenticate_user!` (is logged in) but not `require_admin!` (is admin).

### HTTP Method Confusion

Verify that state-changing operations require appropriate HTTP methods:
- DELETE should not be triggerable via GET
- PUT/PATCH should not fall back to GET-accessible routes
- Check Rails `resources` for any non-standard `:via` configurations

### Before-Action / Filter Gaps in Rails

```ruby
class DocumentsController < ApplicationController
  before_action :authenticate_user!
  before_action :set_document, only: [:show, :update, :destroy]
  before_action :authorize_document!, only: [:update, :destroy]
  # Gap: :show has no authorization check — can view any document
  # Gap: :index may not be scoped to current_user's documents
end
```

Inspect every `before_action` with an `only:` list. Verify that actions omitted from
the `:only` list either (a) don't need authorization (truly public) or (b) have their
own inline authorization.

### Decorator Gaps in Python (FastAPI / Flask)

```python
@app.route("/documents/<int:doc_id>", methods=["GET", "PUT", "DELETE"])
@login_required  # Checks login — but not document ownership
def document_detail(doc_id):
    doc = Document.query.get(doc_id)  # IDOR — no ownership check
    if request.method == "DELETE":
        ...
```

Verify that route decorators validate ownership/permissions, not just authentication.

Reference: OWASP ASVS v4.0 §4.1 (General Access Control Design), CWE-285

---

## Audit Area 5: Token and Claim Validation

Even when AuthN/AuthZ happens upstream, the application often receives a token or
session that it must validate correctly. Incomplete validation creates escalation paths.

### JWT / Bearer Token Claim Validation

If the application receives a JWT from an upstream identity provider, verify:

1. **Algorithm enforcement:** Is `alg` validated? Flag any JWT library configured to
   accept `"alg": "none"` or that does not explicitly specify the expected algorithm.
   (CVE-2015-9235 class of vulnerabilities)

2. **Audience (`aud`) claim:** Is the JWT audience validated? A JWT issued for
   service A should be rejected by service B if audience validation is enforced.

3. **Issuer (`iss`) claim:** Is the issuer validated? Prevents use of tokens from
   a different identity provider.

4. **Expiry (`exp`) claim:** Is expiry enforced, or are expired tokens accepted?

5. **Role/permission claims:** If the JWT contains role or permission claims that
   the application acts on, are those claims treated as authoritative, or can they
   be supplemented/overridden by request parameters?

### Session / Cookie Tampering

If the application uses server-side sessions passed via cookie:
- Is the session signed and/or encrypted? (Rails: encrypted cookie store by default;
  Flask: signed but not encrypted by default with `flask.session`)
- Can a user modify session values by manipulating the cookie?
- Is `httponly` set on session cookies? (Mitigates XSS-based session theft)
- Is `secure` set on session cookies? (Prevents transmission over HTTP)
- Is `samesite=strict` or `samesite=lax` set? (CSRF mitigation)

---

## Audit Area 6: Business Logic and Workflow Bypasses

These are the hardest category for any tool — human or AI — to find, because they
require understanding the intended business rules.

### State Machine / Workflow Bypasses

If the application has objects with a `status` or `state` field:
- Can a user transition an object to a state they should not be able to reach
  directly? (e.g., setting `status=approved` without going through `pending` → review)
- Are state transitions validated server-side, or does the client pass the target
  state in the request?
- Can a user re-open a closed/completed record that should be immutable?

### Race Conditions on Limits

```ruby
# Vulnerable to TOCTOU — two concurrent requests both pass the check
if current_user.api_calls_today < 1000
  make_api_call
  current_user.increment(:api_calls_today)
end
```

Look for check-then-act patterns on any limit (rate limits, credit balances, quota
checks, coupon redemption, invite counts). These require database-level locking or
atomic operations to be safe. Flag any limit enforcement that does not use
`SELECT FOR UPDATE`, atomic increments, or equivalent mechanisms.

Reference: CWE-362 (Concurrent Execution Using Shared Resource with Improper Synchronization)

### Coupon / Discount Stacking and Reuse

In any system with promotional codes, discounts, or credits:
- Can the same coupon be applied multiple times?
- Can multiple coupons be stacked when the intent is single-use?
- Is coupon redemption checked and recorded atomically?

### Indirect Privilege Escalation Through Invitation / Sharing

If the application has an invitation or resource-sharing feature:
- Can a user invite another user and grant them a *higher* permission level than
  the inviter themselves has?
- Can sharing a resource grant the recipient access to parent resources that were
  not explicitly shared?

---

## Output Instructions

For each finding, use the standard schema from `vibe-security-entrypoint`.
Use category tag: `PRIV-ESC`.

After individual findings, append an **Authorization Coverage Matrix**:

```
## Authorization Coverage Matrix

| Endpoint | HTTP Methods | Auth Check | Ownership Scoped? | Role Checked? | Gap? |
|----------|-------------|------------|------------------|---------------|------|
| /orders | GET, POST | Yes | GET: No, POST: N/A | No | IDOR on GET |
| /orders/:id | GET, PATCH, DELETE | Yes | Yes | No | None |
| /orders/export | GET | Yes | No | No | IDOR + no rate limit |
| /admin/orders | GET | Yes | N/A | No | Missing role check |
```

This matrix is the single highest-value output for developers remediating access
control issues — it makes gaps visible at a glance rather than requiring reading
individual findings.
