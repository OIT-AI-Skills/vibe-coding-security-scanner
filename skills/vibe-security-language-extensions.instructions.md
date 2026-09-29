---
description: >
  Language-specific security rules that extend the four core audit skills.
  Applied automatically based on the detected stack. Contains addenda for
  Ruby/Rails, Python, and a template for adding additional languages.
  Focus is on what language-specific SAST tools miss or what applies only
  to frameworks/patterns unique to each language.
---

# Vibe-Coded Application Security Review — Language-Specific Extensions

## How This Skill Is Applied

This skill is loaded by the entrypoint skill after tech stack detection. Apply only
the section(s) matching the detected stack. If multiple languages are present
(e.g., a Python API with a Node.js frontend), apply all relevant sections.

---

## Section A: Ruby on Rails

### Scope Note

Brakeman covers: SQL injection via string interpolation, `permit!` mass assignment,
XSS in views, command injection, unsafe redirects, CSRF token issues, unsafe
deserialization (`Marshal.load`, `YAML.load` without safe load), session secret
checks, and several other categories. The rules below focus on gaps Brakeman does
not address or addresses only partially.

---

### A1. Authorization Callback Coverage (Scope Gaps)

Go beyond Brakeman's mass assignment check and audit the `before_action` chain for
every controller. For each controller:

1. List all actions (`index`, `show`, `new`, `create`, `edit`, `update`, `destroy`,
   plus any custom actions)
2. Identify which `before_action` callbacks apply to each action
3. Verify that the authorization callback (whether Pundit's `authorize`, CanCanCan's
   `load_and_authorize_resource`, Devise's `authenticate_user!`, or a custom method)
   covers **every** action

**Common gap — custom actions excluded from authorization:**
```ruby
before_action :authorize_document!, only: [:update, :destroy]
# 'download', 'share', 'archive' actions added later — never added to :only list
def download; end  # No authorization check
def share; end     # No authorization check
```

**Common gap — `skip_before_action` without documented justification:**
```ruby
skip_before_action :authenticate_user!, only: [:webhook_callback]
# Is this endpoint truly public? Does it validate the webhook signature instead?
```
Flag every `skip_before_action` or `skip_authorization_check`. Each requires a
verified alternative security control or explicit documentation of why it is safe.

---

### A2. Pundit and CanCanCan — Policy/Ability Gaps

**Pundit:**
- Is `policy_scope` called on every collection query in index actions? A missing
  `policy_scope` means all records are returned regardless of user permissions.
  ```ruby
  # Vulnerable — returns all documents
  @documents = Document.all
  # Correct — returns only documents the user is permitted to see
  @documents = policy_scope(Document)
  ```
- Is `verify_authorized` and `verify_policy_scoped` enabled in `ApplicationController`?
  These guard rails raise an error if any action skips Pundit — they are the safety
  net that prevents silent authorization gaps.
- In policy files, are `update?` and `destroy?` distinct from `show?`? A policy that
  grants `show?` but returns `true` in `update?` by default is a common copy-paste error.

**CanCanCan:**
- Is `load_and_authorize_resource` applied to all controllers, or is authorization
  done manually in some? Manual authorization without CanCanCan helpers must be
  audited individually.
- Are `:only`/`:except` options on `load_and_authorize_resource` creating gaps?
- Check `ability.rb` for `can :manage, :all` (grants everything to a role) and
  verify it is gated on a narrow role condition.

---

### A3. ActiveRecord Scope Leakage (IDOR via ORM)

Rails developers often add a `default_scope` intending to filter records globally,
then are surprised when it doesn't apply in all contexts. More commonly, vibe-coded
apps simply lack scoping.

Look for all `Model.find(...)`, `Model.where(...)`, `Model.all` calls in controllers
and service objects. For each one:
- Is the query chained from `current_user.association` (safe)?
- Or is it a top-level query (`Order.find(params[:id])`) without a user scope (IDOR)?

Also check for `unscoped` usage — this explicitly bypasses any `default_scope` and
can re-introduce IDOR if default_scope was the only access control.

---

### A4. Dynamic Dispatch — `send`, `constantize`, `eval`

Brakeman catches `eval` but may miss dynamic dispatch patterns that vibe-coded apps
introduce when generating flexible/generic code.

**`send` with user-controlled method name:**
```ruby
# Critical — arbitrary method call on any object
user.send(params[:action])
model.send("#{params[:field]}=", params[:value])
```

**`constantize` with user-controlled input:**
```ruby
# Critical — can instantiate arbitrary classes, including those with dangerous
# initializers (e.g., File, Net::HTTP)
klass = params[:type].constantize
klass.new.process(params[:data])
```

**`class_eval` / `instance_eval` with user input:**
```ruby
Object.class_eval(params[:code])  # RCE
```

Flag any of these patterns where the method name, constant, or code string is
derived from user input. Severity: **Critical**.

Reference: CWE-470 (Use of Externally-Controlled Input to Select Classes or Code)

---

### A5. ActionCable Channel Authorization

ActionCable (WebSocket) channels are not covered by the HTTP `before_action` chain.
They require their own authorization in the `subscribed` method.

```ruby
class RoomChannel < ApplicationCable::Channel
  def subscribed
    room = Room.find(params[:room_id])
    # Missing: verify current_user is a member of this room
    stream_for room  # Any authenticated user can subscribe to any room
  end
end
```

For each `ApplicationCable::Channel` subclass:
1. Verify that `connection.rb` authenticates the WebSocket connection (sets
   `current_user` or equivalent)
2. Verify that each channel's `subscribed` method checks authorization for the
   specific resource being streamed, not just that a user is present

---

### A6. Rails Engine and Mounted Application Authorization

```ruby
# config/routes.rb
mount Sidekiq::Web => '/sidekiq'           # Needs auth constraint
mount PgHero::Engine, at: 'pghero'         # Needs auth constraint
mount Rswag::Api::Engine => '/api-docs'    # May expose API structure
```

Every mounted engine should have an authentication and authorization constraint:
```ruby
authenticate :user, ->(u) { u.admin? } do
  mount Sidekiq::Web => '/sidekiq'
end
```

Flag any `mount` statement without an `authenticate` or `constraints` wrapper.
Sidekiq Web, PgHero, RailsAdmin, ActiveAdmin (if misconfigured), Flipper UI,
and similar admin engines are particularly high risk if publicly accessible.

---

### A7. Serializer Field Exposure (ActiveModel Serializers, Jbuilder, JSONAPI)

API responses that include fields beyond what is necessary are an information
disclosure risk. Vibe-coded apps frequently expose all model attributes.

```ruby
# Jbuilder — explicit field exposure (review each field)
json.extract! @user, :id, :email, :name, :role, :api_token, :encrypted_password
#                                         ^^^^   ^^^^^^^^^   ^^^^^^^^^^^^^^^^^^
#                                         Review  Sensitive   CRITICAL

# ActiveModel Serializer with all attributes
class UserSerializer < ActiveModel::Serializer
  attributes :id, :email, :name, :admin, :stripe_customer_id, :internal_notes
  #                               ^^^^^                         ^^^^^^^^^^^^^^
end
```

For each serializer or JSON builder, flag:
- Authentication material: `api_token`, `password_digest`, `encrypted_password`,
  `reset_password_token`, `confirmation_token`, `remember_token`
- Internal flags: `admin`, `is_staff`, `internal_notes`, `flags`
- PII beyond what the frontend requires: `ssn`, `date_of_birth`, `full_address`

---

### A8. `after_commit` Callbacks Triggering External Services

```ruby
class Order < ApplicationRecord
  after_commit :sync_to_crm, on: [:create, :update]

  private

  def sync_to_crm
    CrmService.new.upsert(self.attributes)  # Sends all attributes including sensitive fields
  end
end
```

Review every `after_commit`, `after_create`, `after_update`, `after_save` callback
that makes an external call. Verify:
- Only necessary fields are sent (not `self.attributes` wholesale)
- The callback does not trigger on records the current user should not be updating
  (though this is less common since callbacks are model-level)

---

## Section B: Python

### Scope Note

Bandit covers: `assert` in non-test code, `exec`/`eval`, some hardcoded passwords,
`subprocess` with `shell=True`, weak cryptography, XML external entity (XXE),
`pickle` deserialization, `yaml.load` without safe loader, Flask debug mode, and
several other categories. The rules below focus on gaps Bandit does not address.

---

### B1. Framework-Specific Authorization Patterns

#### FastAPI — Dependency Injection Auth

FastAPI uses dependency injection for authentication. The pattern is safe when used
correctly, but vibe-coded apps often apply dependencies inconsistently.

```python
# Correct — dependency enforces auth on this route
@app.get("/orders/{order_id}")
async def get_order(order_id: int, current_user: User = Depends(get_current_user)):
    order = db.query(Order).filter(Order.id == order_id).first()
    # Missing: verify order.user_id == current_user.id (IDOR)

# Common gap — dependency declared but not applied
@app.delete("/orders/{order_id}")  # No Depends(get_current_user) — public endpoint
async def delete_order(order_id: int, db: Session = Depends(get_db)):
    ...
```

For every route: verify that `Depends(get_current_user)` (or equivalent) is present.
For every resource lookup: verify ownership is checked after retrieval.

Also check the `get_current_user` dependency itself — does it validate the token
properly, or does it return a default/anonymous user on failure?

#### Flask — `g.user` and `login_required` Patterns

```python
# Common vibe-coded pattern — decorator on some routes, missing on others
@app.route("/profile")
@login_required  # Protected
def profile():
    ...

@app.route("/profile/export")  # Missing @login_required
def profile_export():
    user_id = request.args.get('user_id')  # Also: IDOR
    ...
```

Check every route for presence of the auth decorator. Also check that `g.user` is
not accessed in undecorated routes (it will be `None`, causing errors or bypass).

#### Django — `get_object_or_404` Scoping

```python
# Vulnerable — returns any document by primary key
document = get_object_or_404(Document, pk=document_id)

# Correct — scopes to the current user
document = get_object_or_404(Document, pk=document_id, owner=request.user)
```

Every `get_object_or_404` call should include a field that scopes to the current
user unless the resource is genuinely public. Flag unscoped lookups.

Also check `@login_required` vs. `@permission_required` decorator usage on Django
views. `@login_required` only checks authentication; permission-sensitive views
need `@permission_required` or manual permission checks.

---

### B2. Celery Task Authorization

Celery tasks run asynchronously, outside the request context. Vibe-coded apps
often queue tasks with user-supplied parameters and perform no authorization check
inside the task itself.

```python
@celery.task
def export_user_data(user_id, requesting_user_id):
    # Does this check that requesting_user_id is authorized to export user_id's data?
    user = User.query.get(user_id)
    return generate_export(user)
```

For each Celery (or RQ, Dramatiq) task that operates on user data:
1. Identify all ID parameters
2. Verify the task re-validates that the requesting context is authorized to
   perform the operation on the target resource
3. Flag tasks that trust user_id parameters without authorization checks

---

### B3. Jinja2 Template Injection (SSTI)

Bandit flags `render_template_string` in some contexts. Extend this check:

```python
# Critical — user controls template string (SSTI → RCE)
template = request.args.get('template')
return render_template_string(template)

# Critical — f-string construction of template from user input
template_str = f"Hello {user_name}, your order is {order_status}"
return render_template_string(template_str)  # user_name could contain {{ 7*7 }}

# Also check Jinja2 Environment instantiation:
env = Environment()  # autoescape=False by default — XSS if rendering HTML
env = Environment(autoescape=False, ...)  # Explicit — flag if used with HTML output
```

For any template rendered with `render_template_string`, verify the template
string is a hardcoded literal, not constructed from user input.

Reference: CWE-94 (Improper Control of Generation of Code), OWASP A03:2021

---

### B4. SQLAlchemy Raw Query Injection

Bandit catches `execute(string)` patterns in some configurations. Extend the check:

```python
# Vulnerable — f-string in text() call bypasses ORM parameterization
query = text(f"SELECT * FROM users WHERE name = '{name}'")
db.execute(query)

# Also vulnerable — string concatenation
db.execute("SELECT * FROM orders WHERE status = '" + status + "'")

# Bandit may not catch this pattern:
db.execute(text(f"UPDATE users SET role = '{role}' WHERE id = {user_id}"))

# Safe — parameterized
db.execute(text("SELECT * FROM users WHERE name = :name"), {"name": name})
```

Flag any `text()`, `execute()`, or `connection.execute()` call where the string
argument is constructed with f-strings, `%` formatting, or `+` concatenation
involving any variable.

---

### B5. `__import__`, `importlib`, and Dynamic Module Loading

```python
# Critical — arbitrary code execution via module import
module_name = request.args.get('plugin')
module = __import__(module_name)

module = importlib.import_module(request.json['adapter'])
```

Flag any dynamic import where the module name is derived from user input.

Also check for plugin/adapter patterns common in vibe-coded apps where a
configuration value (which may be user-settable) is used to determine which
module to load. If users can control the configuration value, flag it.

Reference: CWE-470

---

### B6. `asyncio` Task Context Isolation

In async Python applications (FastAPI, async Django, Starlette), context variables
(`contextvars.ContextVar`) are used to propagate the current user across async
boundaries. If tasks or background coroutines are spawned without proper context
propagation, they may run with the wrong user context — or with no user context,
bypassing auth checks.

```python
# Potentially unsafe — spawned task may not inherit current user context
asyncio.create_task(background_operation(data))

# Safer — explicit context copy
ctx = contextvars.copy_context()
asyncio.create_task(ctx.run(background_operation, data))
```

Flag `asyncio.create_task`, `asyncio.ensure_future`, or `BackgroundTasks.add_task`
(FastAPI) calls that perform authorization-sensitive operations without verifying
that the user context is explicitly passed or copied.

---

### B7. SSRF via User-Controlled URLs in `requests`

Bandit does not flag SSRF. Look for any call where the URL is user-controlled:

```python
# SSRF — user controls the destination
url = request.json.get('webhook_url')
requests.post(url, json=payload)

# Also flag URL construction from database values (if users can set those values)
user = User.query.get(user_id)
requests.get(user.profile_url)  # Is profile_url validated on write?
```

Severity: **High** if arbitrary URLs are accepted; verify that no internal metadata
services (AWS IMDSv1 at `169.254.169.254`, internal APIs) are reachable from the
application's network context.

---

## Section C: Template for Adding a New Language

When extending this skill to cover an additional language, add a new section using
this template. Open a PR against the skill repository.

```markdown
## Section [Letter]: [Language / Framework]

### Scope Note
[Describe what automated SAST tools ARE in the pipeline for this language, if any.
List what those tools cover so reviewers know what this section should NOT duplicate.]

---

### [Letter]1. [Risk Category]
[Description of the risk, code examples showing vulnerable and safe patterns,
CWE reference, severity guidance]

---
### [Letter]2. ...
```

**Minimum required sections for a new language:**
1. Framework-specific authorization pattern gaps (equivalent to A1/B1)
2. ORM/database query injection patterns not caught by SAST (if applicable)
3. Dynamic code execution patterns unique to the language/ecosystem
4. Any deserialization vulnerabilities common to the ecosystem
5. Template/expression injection if the language has a common templating system
