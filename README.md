# Authenticating to MS using OAuth

FastAPI app that authenticates users with **Microsoft Entra (Azure AD)** via OAuth2/OIDC, resolves roles from **Azure AD security group** membership using Microsoft Graph, and protects routes with session-based role dependencies.

---

## Installing

- **Python**: `>=3.14` (see `pyproject.toml`).
- **Package manager**: [uv](https://github.com/astral-sh/uv) or pip.

```bash
# With uv (recommended)
uv sync

# Or with pip
pip install -e .
```

Run the app:

```bash
uv run uvicorn main:app --reload
# or: python -m uvicorn main:app --reload
```

---

## Configuring

### Environment variables

Create a `.env` file in the project root (do **not** commit it; add `.env` to `.gitignore` if using git). Put **all** secrets and **group IDs** in `.env` so they are never checked in.

| Variable | Required | Description |
|----------|----------|-------------|
| `AZURE_TENANT_ID` | Yes | Entra (Azure AD) tenant ID. |
| `AZURE_CLIENT_ID` | Yes | App registration (client) ID. |
| `AZURE_CLIENT_SECRET` | Yes | Client secret for the app registration. |
| `SESSION_SECRET` | Yes (prod) | Secret for signing session cookies. Defaults to `change-me` if unset (unsuitable for production). |
| `admin_group_id` | Yes | Azure AD group GUID; membership grants role `admin`. |
| `support_group_id` | Yes | Azure AD group GUID; membership grants role `support`. |
| `user_group_id` | Yes | Azure AD group GUID; membership grants role `user`. |
| `DEBUG` | No | If set, session stores raw `group_ids` for troubleshooting. |

### Azure app registration

1. In **Microsoft Entra ID** (Azure Portal), create an **App registration**.
2. Under **Certificates & secrets**, create a **Client secret**; use it as `AZURE_CLIENT_SECRET`.
3. Under **API permissions**, add delegated permissions (for the signed-in user):
   - `openid`, `profile`, `email`
   - `User.Read`
   - `GroupMember.Read.All` (for checking group membership via Graph).
4. Under **Authentication**, add a **Web** platform redirect URI:  
   `http://localhost:8000/auth/callback` (or your deployed callback URL).

---

## Decisions

### 20 groups per Graph call

Role membership is resolved with Microsoft Graph **`POST /me/checkMemberGroups`**, which accepts **at most 20 group IDs per request** ([Microsoft docs](https://learn.microsoft.com/en-us/graph/api/user-checkmembergroups)). The app sends **all** configured role group IDs in a **single** request. Therefore:

- **Keep the total number of distinct group IDs in `ROLE_GROUPS` ≤ 20.**  
  If you add more than 20 groups, the Graph call will fail unless the code is extended to **batch** requests (e.g. chunk `groupIds` into batches of 20).

### Role → group mapping and inheritance

- **`ROLE_GROUPS`**: Each role name maps to a **set of Azure AD group GUIDs**. Membership in **any** of those groups grants that role.
- **`ROLE_INHERITS`**: A role can imply others (e.g. `admin` → `support`, `user`). Inherited roles are computed after resolving group membership and are stored in the session together with directly granted roles.
- Only groups that appear in `ROLE_GROUPS` are passed to Graph; no other groups are requested.

### Session and route protection

- **Session**: Cookie-based session (e.g. `SessionMiddleware`) stores `user`, `roles`, and optionally `group_ids` (when `DEBUG` is set).
- **Route protection**: Use `Depends(require_roles("admin"))` for “must have all listed roles”, or `Depends(require_any_role("support", "admin"))` for “must have at least one of these roles”.

### Env and imports

- **`.env`** is loaded with `dotenv` **before** importing `src.msg_auth`, so Azure and session env vars are available when the auth router and provider are created. Keep **group IDs** (e.g. `admin_group_id`, `support_group_id`, `user_group_id`) in `.env` so they are not committed to the repo.
- The `noqa: E402` on imports is to satisfy Ruff’s “no imports after non-import code” rule while still loading `.env` first.

---

## Endpoints

| Path | Description |
|------|-------------|
| `GET /` | Home; returns `logged_in` and `user` from session. |
| `GET /login` | Redirects to Microsoft login. |
| `GET /auth/callback` | OAuth callback; exchanges code, fetches groups via Graph, computes roles, redirects to `/me`. |
| `GET /me` | Current user and roles; redirects to `/login` if not authenticated. |
| `GET /logout` | Clears session and redirects to `/`. |
| `GET /admin` | Protected (requires role `admin`). |
| `GET /support` | Protected (requires role `support`). |
| `GET /support-or-admin` | Protected (requires role `support` or `admin`). |
