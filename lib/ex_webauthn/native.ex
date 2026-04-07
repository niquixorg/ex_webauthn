defmodule ExWebauthn.Native do
  @moduledoc """
  Low-level NIF bindings to webauthn-rs.

  This module should not be called directly — use `ExWebauthn` instead,
  which wraps these functions with JSON encoding/decoding and config
  management via a GenServer.
  """

  version = Mix.Project.config()[:version]

  use RustlerPrecompiled,
    otp_app: :ex_webauthn,
    crate: "ex_webauthn_native",
    base_url: "https://github.com/niquixorg/ex_webauthn/releases/download/v#{version}",
    force_build: System.get_env("EX_WEBAUTHN_BUILD") in ["1", "true"],
    targets: ~w(
      aarch64-apple-darwin
      x86_64-apple-darwin
      x86_64-unknown-linux-gnu
      aarch64-unknown-linux-gnu
      x86_64-unknown-linux-musl
      aarch64-unknown-linux-musl
      x86_64-pc-windows-msvc
    ),
    version: version

  @type error_kind ::
          :invalid_origin
          | :invalid_config
          | :invalid_uuid
          | :invalid_json
          | :not_initialized
          | :registration_failed
          | :authentication_failed
          | :serialization_failed

  @doc """
  Initialize the cached Webauthn instance with relying party config.

  Must be called before any other NIF function. Can be called again
  to reconfigure. Enforces HTTPS except for loopback origins.
  """
  @spec init(String.t(), String.t()) :: {:ok, {}} | {:error, {error_kind(), String.t()}}
  def init(_rp_id, _rp_origin), do: :erlang.nif_error(:nif_not_loaded)

  @doc """
  Begin a passkey registration ceremony.

  Returns `{creation_challenge_json, registration_state_json}` on success.
  The state must be stored server-side and never sent to the client.
  """
  @spec start_registration(String.t(), String.t(), String.t(), String.t()) ::
          {:ok, {String.t(), String.t()}} | {:error, {error_kind(), String.t()}}
  def start_registration(
        _user_unique_id,
        _user_name,
        _user_display_name,
        _exclude_credentials_json
      ),
      do: :erlang.nif_error(:nif_not_loaded)

  @doc """
  Complete a passkey registration ceremony.

  Verifies the browser response against the registration state.
  Returns the serialized credential JSON to persist in the database.
  """
  @spec finish_registration(String.t(), String.t()) ::
          {:ok, String.t()} | {:error, {error_kind(), String.t()}}
  def finish_registration(_registration_state_json, _client_response_json),
    do: :erlang.nif_error(:nif_not_loaded)

  @doc """
  Begin a passkey authentication ceremony.

  Accepts a JSON array of stored credentials. Pass `"[]"` for
  discoverable credential (usernameless) authentication.
  Returns `{request_challenge_json, authentication_state_json}`.
  """
  @spec start_authentication(String.t()) ::
          {:ok, {String.t(), String.t()}} | {:error, {error_kind(), String.t()}}
  def start_authentication(_credentials_json),
    do: :erlang.nif_error(:nif_not_loaded)

  @doc """
  Complete a passkey authentication ceremony.

  Verifies the browser response against the authentication state.
  Returns the serialized authentication result containing the
  credential ID and updated counter value.
  """
  @spec finish_authentication(String.t(), String.t()) ::
          {:ok, String.t()} | {:error, {error_kind(), String.t()}}
  def finish_authentication(_authentication_state_json, _client_response_json),
    do: :erlang.nif_error(:nif_not_loaded)
end
