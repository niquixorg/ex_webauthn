# ExWebauthn

Elixir NIF wrapper for [webauthn-rs](https://github.com/kanidm/webauthn-rs) — passkey registration and authentication backed by Rust.

## Requirements

- Elixir >= 1.19
- Rust >= 1.75 (for NIF compilation)
- OpenSSL dev headers (`libssl-dev` / `openssl-devel`)

## Installation

Add to `mix.exs`:

```elixir
def deps do
  [
    {:ex_webauthn, "~> 0.1.0"}
  ]
end
```

## Configuration

```elixir
# config/dev.exs
config :ex_webauthn,
  rp_id: "localhost",
  rp_origin: "http://localhost:4000"

# config/prod.exs
config :ex_webauthn,
  rp_id: "example.com",
  rp_origin: "https://example.com"
```

HTTPS is enforced for origins. HTTP is allowed only for loopback addresses (`localhost`, `127.0.0.1`, `::1`).

## Setup

Add `ExWebauthn` to your supervision tree:

```elixir
children = [
  ExWebauthn,
  MyAppWeb.Endpoint
]
```

Or with inline config:

```elixir
children = [
  {ExWebauthn, rp_id: "example.com", rp_origin: "https://example.com"}
]
```

## Usage

### Registration

```elixir
# 1. Start — returns challenge options for the browser
{:ok, challenge_options, registration_state} =
  ExWebauthn.start_registration(user_uuid, email, display_name)

# 2. Store registration_state server-side (session, ETS, DB)
# 3. Send challenge_options as JSON to the browser
# 4. Browser calls navigator.credentials.create()

# 5. Finish — verify the browser response
{:ok, credential} =
  ExWebauthn.finish_registration(registration_state, client_response)

# 6. Store credential in your DB
```

### Authentication

```elixir
# 1. Start — pass stored credentials for the user
{:ok, challenge_options, authentication_state} =
  ExWebauthn.start_authentication(stored_credentials)

# 2. Store authentication_state server-side
# 3. Send challenge_options to the browser
# 4. Browser calls navigator.credentials.get()

# 5. Finish — verify the browser response
{:ok, auth_result} =
  ExWebauthn.finish_authentication(authentication_state, client_response)
```

### Discoverable credentials (usernameless)

```elixir
{:ok, challenge_options, authentication_state} =
  ExWebauthn.start_authentication([])
```

### Phoenix controller example

```elixir
defmodule MyAppWeb.WebauthnController do
  use MyAppWeb, :controller

  def register_challenge(conn, %{"user_id" => uid, "email" => email}) do
    {:ok, challenge, state} = ExWebauthn.start_registration(uid, email, email)

    conn
    |> put_session(:webauthn_state, state)
    |> json(challenge)
  end

  def register_verify(conn, %{"response" => response}) do
    state = get_session(conn, :webauthn_state)

    case ExWebauthn.finish_registration(state, response) do
      {:ok, credential} ->
        # persist credential for the user
        conn |> delete_session(:webauthn_state) |> json(%{status: "ok"})

      {:error, _kind, message} ->
        conn |> put_status(400) |> json(%{error: message})
    end
  end
end
```

## Error handling

All functions return `{:error, error_kind, message}` on failure:

```elixir
case ExWebauthn.start_registration(uid, email, name) do
  {:ok, challenge, state} -> # success
  {:error, :invalid_uuid, msg} -> # bad user ID
  {:error, :invalid_origin, msg} -> # bad rp_origin
  {:error, :not_initialized, msg} -> # forgot to add to supervision tree
  {:error, :registration_failed, msg} -> # webauthn-rs rejected it
end
```

Error kinds: `:invalid_origin`, `:invalid_config`, `:invalid_uuid`, `:invalid_json`, `:not_initialized`, `:registration_failed`, `:authentication_failed`, `:serialization_failed`.

## Runtime reload

```elixir
ExWebauthn.reload(rp_id: "new.example.com", rp_origin: "https://new.example.com")
```

## Security

- Crypto and signature verification handled entirely by [webauthn-rs](https://github.com/kanidm/webauthn-rs) (security-audited by SUSE).
- No `unsafe` Rust code — Rustler handles NIF boilerplate.
- `parking_lot::RwLock` used to avoid lock poisoning.
- HTTPS enforced for non-loopback origins.
- Registration/authentication state is opaque and must be stored server-side only.

## License

MIT