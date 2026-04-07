defmodule ExWebauthn do
  @moduledoc """
  Elixir wrapper for webauthn-rs via NIF.

  ## Setup

  Add to your supervision tree:

      children = [
        {ExWebauthn, rp_id: "example.com", rp_origin: "https://example.com"},
        MyAppWeb.Endpoint
      ]

  Or configure via application config:

      # config/config.exs
      config :ex_webauthn,
        rp_id: "localhost",
        rp_origin: "http://localhost:4000"

      # config/prod.exs
      config :ex_webauthn,
        rp_id: "example.com",
        rp_origin: "https://example.com"

  Then add to your supervision tree without options:

      children = [ExWebauthn]

  ## Usage

  ### Registration flow

      # 1. Start registration — send challenge_options to the browser
      {:ok, challenge_options, registration_state} =
        ExWebauthn.start_registration(
          "f47ac10b-58cc-4372-a567-0e02b2c3d479",
          "user@example.com",
          "Jane Doe"
        )

      # 2. Store registration_state server-side (DB, session, ETS)
      # 3. Send challenge_options as JSON to the browser
      # 4. Browser calls navigator.credentials.create() and sends response back

      # 5. Finish registration — verify the browser response
      {:ok, credential} = ExWebauthn.finish_registration(registration_state, client_response)

      # 6. Store credential in your DB for this user

  ### Authentication flow

      # 1. Fetch stored credentials for the user from your DB
      {:ok, challenge_options, authentication_state} =
        ExWebauthn.start_authentication(stored_credentials)

      # 2. Store authentication_state server-side
      # 3. Send challenge_options to the browser
      # 4. Browser calls navigator.credentials.get() and sends response back

      # 5. Finish authentication
      {:ok, auth_result} = ExWebauthn.finish_authentication(authentication_state, client_response)

  ### Discoverable credentials (usernameless login)

      {:ok, challenge_options, authentication_state} =
        ExWebauthn.start_authentication([])
  """

  use GenServer
  alias ExWebauthn.Native

  @type error :: {:error, Native.error_kind(), String.t()}
  @type challenge_options :: map()
  @type credential :: map()
  @type auth_result :: map()

  def child_spec(opts) do
    %{
      id: __MODULE__,
      start: {__MODULE__, :start_link, [opts]},
      type: :worker
    }
  end

  def start_link(opts \\ []) do
    GenServer.start_link(__MODULE__, opts, name: __MODULE__)
  end

  @impl true
  def init(opts) do
    config = Keyword.merge(Application.get_all_env(:ex_webauthn), opts)
    rp_id = Keyword.fetch!(config, :rp_id)
    rp_origin = Keyword.fetch!(config, :rp_origin)

    case Native.init(rp_id, rp_origin) do
      {:ok, {}} ->
        {:ok, %{rp_id: rp_id, rp_origin: rp_origin}}

      {:error, {error_kind, error_message}} ->
        {:stop, {error_kind, error_message}}
    end
  end

  @doc """
  Reload config at runtime. Reads from app env or accepts overrides.

  ## Examples

      ExWebauthn.reload(rp_id: "new.example.com", rp_origin: "https://new.example.com")
      #=> :ok
  """
  @spec reload(keyword()) :: :ok | error()
  def reload(opts \\ []) do
    GenServer.call(__MODULE__, {:reload, opts})
  end

  @impl true
  def handle_call({:reload, opts}, _from, state) do
    config = Keyword.merge(Application.get_all_env(:ex_webauthn), opts)
    rp_id = Keyword.fetch!(config, :rp_id)
    rp_origin = Keyword.fetch!(config, :rp_origin)

    case Native.init(rp_id, rp_origin) do
      {:ok, {}} ->
        {:reply, :ok, %{rp_id: rp_id, rp_origin: rp_origin}}

      {:error, {error_kind, error_message}} ->
        {:reply, {:error, error_kind, error_message}, state}
    end
  end

  @doc """
  Start a passkey registration ceremony.

  Returns challenge options to send to the browser and an opaque registration
  state to store server-side.

  ## Parameters

    * `user_unique_id` - UUID identifying the user
    * `user_name` - human-readable account name (e.g. email)
    * `user_display_name` - friendly display name
    * `exclude_credentials` - list of existing credentials to prevent re-registration

  ## Examples

      {:ok, challenge_options, registration_state} =
        ExWebauthn.start_registration(
          "f47ac10b-58cc-4372-a567-0e02b2c3d479",
          "user@example.com",
          "Jane Doe"
        )

  With exclude credentials:

      {:ok, challenge_options, registration_state} =
        ExWebauthn.start_registration(
          "f47ac10b-58cc-4372-a567-0e02b2c3d479",
          "user@example.com",
          "Jane Doe",
          existing_credentials
        )
  """
  @spec start_registration(
          user_unique_id :: String.t(),
          user_name :: String.t(),
          user_display_name :: String.t(),
          exclude_credentials :: [map()]
        ) :: {:ok, challenge_options(), registration_state :: String.t()} | error()
  def start_registration(user_unique_id, user_name, user_display_name, exclude_credentials \\ []) do
    exclude_credentials_json = Jason.encode!(exclude_credentials)

    case Native.start_registration(
           user_unique_id,
           user_name,
           user_display_name,
           exclude_credentials_json
         ) do
      {:ok, {creation_challenge_json, registration_state_json}} ->
        {:ok, Jason.decode!(creation_challenge_json), registration_state_json}

      {:error, {error_kind, error_message}} ->
        {:error, error_kind, error_message}
    end
  end

  @doc """
  Complete a passkey registration ceremony.

  Verifies the browser's response against the registration state from
  `start_registration/4`. Returns the credential to store in your database.

  ## Parameters

    * `registration_state` - opaque state from `start_registration/4`
    * `client_response` - the browser's `PublicKeyCredential` response as a map

  ## Examples

      {:ok, credential} =
        ExWebauthn.finish_registration(registration_state, client_response)
  """
  @spec finish_registration(registration_state :: String.t(), client_response :: map()) ::
          {:ok, credential()} | error()
  def finish_registration(registration_state, client_response) do
    client_response_json = Jason.encode!(client_response)

    case Native.finish_registration(registration_state, client_response_json) do
      {:ok, credential_json} -> {:ok, Jason.decode!(credential_json)}
      {:error, {error_kind, error_message}} -> {:error, error_kind, error_message}
    end
  end

  @doc """
  Start a passkey authentication ceremony.

  Pass the user's stored credentials, or an empty list for discoverable
  credential (usernameless) authentication.

  ## Parameters

    * `credentials` - list of stored credentials for the user, or `[]` for discoverable flow

  ## Examples

      # With known user credentials
      {:ok, challenge_options, authentication_state} =
        ExWebauthn.start_authentication(user_credentials)

      # Discoverable / usernameless login
      {:ok, challenge_options, authentication_state} =
        ExWebauthn.start_authentication([])
  """
  @spec start_authentication(credentials :: [map()]) ::
          {:ok, challenge_options(), authentication_state :: String.t()} | error()
  def start_authentication(credentials) do
    credentials_json = Jason.encode!(credentials)

    case Native.start_authentication(credentials_json) do
      {:ok, {request_challenge_json, authentication_state_json}} ->
        {:ok, Jason.decode!(request_challenge_json), authentication_state_json}

      {:error, {error_kind, error_message}} ->
        {:error, error_kind, error_message}
    end
  end

  @doc """
  Complete a passkey authentication ceremony.

  Verifies the browser's response against the authentication state from
  `start_authentication/1`. Returns the authentication result which may
  contain updated credential counter info.

  ## Parameters

    * `authentication_state` - opaque state from `start_authentication/1`
    * `client_response` - the browser's `PublicKeyCredential` response as a map

  ## Examples

      {:ok, auth_result} =
        ExWebauthn.finish_authentication(authentication_state, client_response)
  """
  @spec finish_authentication(authentication_state :: String.t(), client_response :: map()) ::
          {:ok, auth_result()} | error()
  def finish_authentication(authentication_state, client_response) do
    client_response_json = Jason.encode!(client_response)

    case Native.finish_authentication(authentication_state, client_response_json) do
      {:ok, authentication_result_json} -> {:ok, Jason.decode!(authentication_result_json)}
      {:error, {error_kind, error_message}} -> {:error, error_kind, error_message}
    end
  end
end
