use parking_lot::RwLock;
use rustler::Atom;
use serde_json;
use url::Url;
use webauthn_rs::prelude::*;
use webauthn_rs::WebauthnBuilder;

mod atoms {
    rustler::atoms! {
        invalid_origin,
        invalid_config,
        invalid_uuid,
        invalid_json,
        not_initialized,
        registration_failed,
        authentication_failed,
        serialization_failed,
    }
}

/// Cached `Webauthn` instance. Initialized once via `init/2`, then read
/// concurrently by all NIF calls. Write lock is only held during `init`.
static WEBAUTHN: RwLock<Option<Webauthn>> = RwLock::new(None);

fn is_loopback_host(host: Option<&str>) -> bool {
    matches!(host, Some("localhost" | "127.0.0.1" | "::1" | "[::1]"))
}


/// Acquires a read lock on the cached `Webauthn` instance and passes
/// a reference to the provided closure. Returns `not_initialized` error
/// if `init/2` has not been called.
fn with_webauthn<F, T>(operation: F) -> Result<T, (Atom, String)>
where
    F: FnOnce(&Webauthn) -> Result<T, (Atom, String)>,
{
    let guard = WEBAUTHN.read();
    let webauthn = guard
        .as_ref()
        .ok_or_else(|| (atoms::not_initialized(), "call ExWebauthn.init/2 first".to_string()))?;
    operation(webauthn)
}

/// Initialize the WebAuthn instance with relying party config.
///
/// Must be called before any other NIF function. Can be called again
/// to reconfigure (e.g. config reload). The write lock is held only
/// for the duration of the swap.
///
/// Enforces HTTPS for origins, with an exception for loopback addresses
/// (localhost, 127.0.0.1, ::1) to support local development.
#[rustler::nif]
fn init(rp_id: &str, rp_origin: &str) -> Result<(), (Atom, String)> {
    let origin = Url::parse(rp_origin).map_err(|e| (atoms::invalid_origin(), e.to_string()))?;

    match origin.scheme() {
        "https" => {}
        "http" if is_loopback_host(origin.host_str()) => {}
        _ => {
            return Err((
                atoms::invalid_origin(),
                "origin must be https (http allowed only for loopback)".to_string(),
            ))
        }
    }

    let builder = WebauthnBuilder::new(rp_id, &origin)
        .map_err(|e| (atoms::invalid_config(), e.to_string()))?;
    let webauthn = builder
        .build()
        .map_err(|e| (atoms::invalid_config(), e.to_string()))?;

    *WEBAUTHN.write() = Some(webauthn);

    Ok(())
}

/// Begin a passkey registration ceremony.
///
/// Generates a cryptographic challenge and returns:
/// - `creation_challenge_json`: challenge options to send to the browser
/// - `registration_state_json`: opaque state to store server-side
///
/// The `exclude_credentials_json` parameter accepts a JSON array of
/// existing `Passkey` credentials to prevent re-registration of the
/// same authenticator.
#[rustler::nif]
fn start_registration(
    user_unique_id: &str,
    user_name: &str,
    user_display_name: &str,
    exclude_credentials_json: &str,
) -> Result<(String, String), (Atom, String)> {
    with_webauthn(|webauthn| {
        let user_unique_id =
            Uuid::parse_str(user_unique_id).map_err(|e| (atoms::invalid_uuid(), e.to_string()))?;

        let exclude_credentials: Vec<Passkey> =
            serde_json::from_str(exclude_credentials_json)
                .map_err(|e| (atoms::invalid_json(), e.to_string()))?;

        let exclude_credential_ids: Option<Vec<CredentialID>> =
            if exclude_credentials.is_empty() {
                None
            } else {
                Some(
                    exclude_credentials
                        .iter()
                        .map(|credential| credential.cred_id().clone())
                        .collect(),
                )
            };

        let (creation_challenge, registration_state) = webauthn
            .start_passkey_registration(
                user_unique_id,
                user_name,
                user_display_name,
                exclude_credential_ids,
            )
            .map_err(|e| (atoms::registration_failed(), e.to_string()))?;

        let creation_challenge_json = serde_json::to_string(&creation_challenge)
            .map_err(|e| (atoms::serialization_failed(), e.to_string()))?;
        let registration_state_json = serde_json::to_string(&registration_state)
            .map_err(|e| (atoms::serialization_failed(), e.to_string()))?;

        Ok((creation_challenge_json, registration_state_json))
    })
}


/// Complete a passkey registration ceremony.
///
/// Verifies the browser's `RegisterPublicKeyCredential` response against
/// the registration state from `start_registration`. Returns the serialized
/// `Passkey` credential to persist in the database.
///
/// The `registration_state_json` must be the exact opaque state returned
/// by `start_registration` — do not send this to the client.
#[rustler::nif]
fn finish_registration(
    registration_state_json: &str,
    client_response_json: &str,
) -> Result<String, (Atom, String)> {
    with_webauthn(|webauthn| {
        let registration_state: PasskeyRegistration =
            serde_json::from_str(registration_state_json)
                .map_err(|e| (atoms::invalid_json(), e.to_string()))?;

        let register_response: RegisterPublicKeyCredential =
            serde_json::from_str(client_response_json)
                .map_err(|e| (atoms::invalid_json(), e.to_string()))?;

        let credential = webauthn
            .finish_passkey_registration(&register_response, &registration_state)
            .map_err(|e| (atoms::registration_failed(), e.to_string()))?;

        serde_json::to_string(&credential)
            .map_err(|e| (atoms::serialization_failed(), e.to_string()))
    })
}

/// Begin a passkey authentication ceremony.
///
/// Accepts a JSON array of stored `Passkey` credentials for the user.
/// Pass `"[]"` for discoverable credential (usernameless) authentication.
///
/// Returns:
/// - `request_challenge_json`: challenge options to send to the browser
/// - `authentication_state_json`: opaque state to store server-side
#[rustler::nif]
fn start_authentication(
    credentials_json: &str,
) -> Result<(String, String), (Atom, String)> {
    with_webauthn(|webauthn| {
        let credentials: Vec<Passkey> = serde_json::from_str(credentials_json)
            .map_err(|e| (atoms::invalid_json(), e.to_string()))?;

        let (request_challenge, authentication_state) = webauthn
            .start_passkey_authentication(&credentials)
            .map_err(|e| (atoms::authentication_failed(), e.to_string()))?;

        let request_challenge_json = serde_json::to_string(&request_challenge)
            .map_err(|e| (atoms::serialization_failed(), e.to_string()))?;
        let authentication_state_json = serde_json::to_string(&authentication_state)
            .map_err(|e| (atoms::serialization_failed(), e.to_string()))?;

        Ok((request_challenge_json, authentication_state_json))
    })
}

/// Complete a passkey authentication ceremony.
///
/// Verifies the browser's `PublicKeyCredential` response against
/// the authentication state from `start_authentication`. Returns the
/// serialized `AuthenticationResult` which contains the credential ID
/// and updated counter value.
///
/// The caller should update the stored credential's counter if the
/// result indicates it needs updating (to detect cloned authenticators).
#[rustler::nif]
fn finish_authentication(
    authentication_state_json: &str,
    client_response_json: &str,
) -> Result<String, (Atom, String)> {
    with_webauthn(|webauthn| {
        let authentication_state: PasskeyAuthentication =
            serde_json::from_str(authentication_state_json)
                .map_err(|e| (atoms::invalid_json(), e.to_string()))?;

        let authentication_response: PublicKeyCredential =
            serde_json::from_str(client_response_json)
                .map_err(|e| (atoms::invalid_json(), e.to_string()))?;

        let authentication_result = webauthn
            .finish_passkey_authentication(&authentication_response, &authentication_state)
            .map_err(|e| (atoms::authentication_failed(), e.to_string()))?;

        serde_json::to_string(&authentication_result)
            .map_err(|e| (atoms::serialization_failed(), e.to_string()))
    })
}

rustler::init!("Elixir.ExWebauthn.Native");