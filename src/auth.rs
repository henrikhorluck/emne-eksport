use std::time::Duration;

use anyhow::anyhow;
use log::debug;
use openidconnect::{
    core::{CoreClient, CoreProviderMetadata, CoreResponseType},
    reqwest::async_http_client,
    AccessToken, AccessTokenHash, AuthenticationFlow, AuthorizationCode, ClientId, ClientSecret,
    CsrfToken, IssuerUrl, Nonce, OAuth2TokenResponse, PkceCodeChallenge, RedirectUrl, Scope,
    TokenResponse,
};

use serde::Deserialize;
use tokio::sync::mpsc::Receiver;
use warp::Filter;
use warp::Rejection;

const RETURN_MESSAGE: &str = "Go back to your terminal :)";

#[derive(Deserialize, Debug)]
struct OidcQuery {
    code: AuthorizationCode,
    state: CsrfToken,
}

fn setup_server() -> (
    Receiver<OidcQuery>,
    Receiver<()>,
    warp::filters::BoxedFilter<(String,)>,
) {
    let (q_tx, q_rx) = tokio::sync::mpsc::channel::<OidcQuery>(1);
    let (shutdown_tx, shutdown_rx) = tokio::sync::mpsc::channel::<()>(1);

    let route = warp::path::end()
        .and(warp::query::<OidcQuery>())
        .and_then(move |query: OidcQuery| {
            let q_tx = q_tx.clone();
            let shutdown_tx = shutdown_tx.clone();

            async move {
                q_tx.send(query)
                    .await
                    .expect("unable to forward data from server");
                shutdown_tx
                    .send(())
                    .await
                    .expect("unable to shutdown server");
                Ok::<String, Rejection>(RETURN_MESSAGE.into())
            }
        })
        .boxed();
    (q_rx, shutdown_rx, route)
}

pub(crate) async fn authenticate(
    client_id: ClientId,
    client_secret: ClientSecret,
    redirect_port: u16,
) -> Result<AccessToken, anyhow::Error> {
    let provider_metadata = CoreProviderMetadata::discover_async(
        IssuerUrl::new("https://auth.dataporten.no".to_string())?,
        async_http_client,
    )
    .await?;

    let client =
        CoreClient::from_provider_metadata(provider_metadata, client_id, Some(client_secret))
            .set_redirect_uri(RedirectUrl::new(format!(
                "http://localhost:{}",
                redirect_port
            ))?);

    let (pkce_challenge, pkce_verifier) = PkceCodeChallenge::new_random_sha256();
    let (authorize_url, csrf_token, nonce) = client
        .authorize_url(
            AuthenticationFlow::<CoreResponseType>::AuthorizationCode,
            CsrfToken::new_random,
            Nonce::new_random,
        )
        .add_scope(Scope::new("groups-edu".to_string()))
        .add_scope(Scope::new("profile".to_string()))
        .add_scope(Scope::new("openid".to_string()))
        .add_scope(Scope::new("userid".to_string()))
        .set_pkce_challenge(pkce_challenge)
        .url();

    println!("Open this URL in your browser:\n{}\n", authorize_url);

    let (mut q_rx, mut shutdown_rx, route) = setup_server();

    let (_addr, server) = warp::serve(route).bind_with_graceful_shutdown(
        ([127, 0, 0, 1], redirect_port),
        // Prepare some signal for when the server should start shutting down...
        async move {
            shutdown_rx
                .recv()
                .await
                .expect("failed to receive shutdown");
        },
    );

    let thread_handle = tokio::task::spawn(server);

    // And later, trigger the signal by calling `tx.send(())`.
    let q = tokio::time::timeout(Duration::from_secs(60), q_rx.recv())
        .await
        .expect("Didn't log in in time")
        .expect("Didn't log in in time");
    let (code, state) = (q.code, q.state);

    debug!("Feide returned the following code:\n{}\n", code.secret());
    debug!(
        "Feide returned the following state:\n{} (expected `{}`)\n",
        state.secret(),
        csrf_token.secret()
    );

    // Exchange the code with a token.
    let token_response = client
        .exchange_code(code)
        .set_pkce_verifier(pkce_verifier)
        .request_async(async_http_client)
        .await?;

    let id_token = token_response
        .id_token()
        .ok_or_else(|| anyhow!("Server did not return an ID token"))?;

    // TODO: this step failed?
    let claims = id_token.claims(&client.id_token_verifier(), &nonce)?;
    debug!("Feide returned ID token: {:?}", id_token);
    // Verify the access token hash to ensure that the access token hasn't been substituted for
    // another user's.
    if let Some(expected_access_token_hash) = claims.access_token_hash() {
        let actual_access_token_hash =
            AccessTokenHash::from_token(token_response.access_token(), &id_token.signing_alg()?)?;
        if actual_access_token_hash != *expected_access_token_hash {
            return Err(anyhow!("Invalid access token"));
        }
    }

    thread_handle.await?;
    Ok(token_response.access_token().to_owned())
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::time::timeout;

    #[tokio::test]
    async fn test_filter() {
        let (mut q_rx, mut shutdown_rx, filter) = setup_server();

        let code = "bc8ebda9625e4067b6633f9edce4af46";
        let state = "eLEMZJlCgDXh_JV02mi8lw";

        let return_message = warp::test::request()
            .path(&format!("/?code={code}&state={state}").to_string())
            .filter(&filter)
            .await
            .unwrap();

        assert_eq!(return_message, RETURN_MESSAGE);

        let q = timeout(Duration::from_secs(1), q_rx.recv())
            .await
            .expect("failed to send query params")
            .expect("failed to send query params");

        assert_eq!(q.code.secret(), code);
        assert_eq!(q.state.secret(), state);
        timeout(Duration::from_secs(1), shutdown_rx.recv())
            .await
            .expect("failed to send shutdown signal")
            .expect("failed send shutdown signal");
    }
}
