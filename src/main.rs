#![deny(rust_2018_idioms)]
#![allow(dead_code)]

use anyhow::anyhow;
use chrono::prelude::*;
use chrono::DateTime;
use clap::Parser;
use fantoccini::wd::Capabilities;

use log::debug;
use openidconnect::core::{CoreClient, CoreProviderMetadata, CoreResponseType};
use openidconnect::reqwest::async_http_client;
use openidconnect::{
    AccessTokenHash, AuthenticationFlow, AuthorizationCode, ClientId, ClientSecret, CsrfToken,
    IssuerUrl, Nonce, OAuth2TokenResponse, PkceCodeChallenge, RedirectUrl, Scope, TokenResponse,
};
use serde::Deserialize;
use std::convert::Infallible;
use std::fs;
use std::path::PathBuf;
use std::time::Duration;
use tokio::sync::mpsc::Receiver;
use warp::Filter;
use warp::Rejection;
use webdriver::command::{PrintParameters, WebDriverCommand};

const WEB_DRIVER_CAPABILITIES: &str = include_str!("WebDriverCapabilities.json");
const RETURN_MESSAGE: &str = "Go back to your terminal :)";

#[derive(Debug, Deserialize)]
struct Emne {
    id: String,
    #[serde(rename = "type")]
    emne_type: String,
    parent: String,
    membership: Membership,
    #[serde(rename = "displayName")]
    display_name: String,
}

impl Emne {
    fn year_taken(&self) -> i32 {
        let now = Utc::now();
        // not_after is set to ~14. August if it is spring, and 12. December if autumn
        match self.membership.not_after {
            Some(y) if y.month() > Month::September as u32 => y.year(),
            Some(y) => y.year() - 1,
            None if now.month() > Month::August as u32 => now.year(),
            None => now.year() - 1,
        }
    }

    fn emne_code(&self) -> &str {
        self.id.split(':').nth(5).unwrap()
    }

    fn uri(&self) -> String {
        // TODO: support 1. localization, 2. different universities by reading from the id
        let emne_code = self.emne_code();
        let year_taken = self.year_taken();
        format!("https://www.ntnu.edu/studies/courses/{emne_code}/{year_taken}")
    }
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct Membership {
    basic: String,
    fsroles: Vec<String>,
    active: bool,
    not_after: Option<DateTime<Utc>>,
    display_name: String,
    subject_relations: Option<String>,
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

#[derive(Deserialize, Debug)]
struct OidcQuery {
    code: AuthorizationCode,
    state: CsrfToken,
}

#[derive(Parser, Debug)]
#[command(version)]
/// Eksporter emnebeskrivelser fra utdanning ved NTNU
struct Cli {
    /// Name of the folder to put the exported PDFs
    #[arg(short = 'd')]
    destination: PathBuf,

    /// OIDC Client ID, can be retrieved from https://dashboard.dataporten.no
    #[arg(env="FEIDE_CLIENT_ID", value_parser=client_id_parser)]
    client_id: ClientId,
    /// OIDC Client Secret, can be retrieved from https://dashboard.dataporten.no
    #[arg(env="FEIDE_CLIENT_SECRET", value_parser=client_secret_parser)]
    client_secret: ClientSecret,
    /// Port of the redirection-URL, which you configured in https://dashboard.dataporten.no
    #[arg(short = 'p', default_value_t = 16453)]
    redirect_port: u16,
}

fn client_id_parser(s: &str) -> Result<ClientId, Infallible> {
    Ok(ClientId::new(s.to_string()))
}

fn client_secret_parser(s: &str) -> Result<ClientSecret, Infallible> {
    Ok(ClientSecret::new(s.to_string()))
}

#[tokio::main]
pub async fn main() -> Result<(), anyhow::Error> {
    env_logger::init();
    let config = Cli::parse();

    let provider_metadata = CoreProviderMetadata::discover_async(
        IssuerUrl::new("https://auth.dataporten.no".to_string())?,
        async_http_client,
    )
    .await?;

    let client = CoreClient::from_provider_metadata(
        provider_metadata,
        config.client_id,
        Some(config.client_secret),
    )
    .set_redirect_uri(RedirectUrl::new(format!(
        "http://localhost:{}",
        config.redirect_port
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
        ([127, 0, 0, 1], config.redirect_port),
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
    let client = reqwest::Client::new();

    let emner: Vec<Emne> = client
        .get("https://groups-api.dataporten.no/groups/me/groups?type=fc:fs:emne") // TODO: this query-param doesn't work
        .bearer_auth(token_response.access_token().secret())
        .send()
        .await?
        .json()
        .await?;

    let mut c = fantoccini::ClientBuilder::native();
    c.capabilities(serde_json::from_str::<Capabilities>(
        WEB_DRIVER_CAPABILITIES,
    )?);

    let browser = c
        .connect("http://localhost:4444")
        .await
        .expect("failed to connect to WebDriver");

    fs::create_dir(&config.destination)?;

    for emne in emner.iter().filter(|e| e.emne_type == "fc:fs:emne") {
        browser.goto(&emne.uri()).await?;
        let data = browser
            .issue_cmd(WebDriverCommand::Print(PrintParameters::default()))
            .await?;
        let pdf = base64::decode(data.as_str().unwrap())?;

        fs::write(
            config.destination.join(format!("{}.pdf", emne.emne_code())),
            pdf,
        )?;
    }

    browser.close().await?;
    thread_handle.await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use clap::CommandFactory;
    use tokio::time::timeout;

    use super::*;

    #[test]
    fn verify_cli() {
        Cli::command().debug_assert();
    }

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

    #[tokio::test]
    async fn test_print_pdf() -> Result<(), anyhow::Error> {
        let mut c = fantoccini::ClientBuilder::native();
        c.capabilities(serde_json::from_str::<Capabilities>(
            WEB_DRIVER_CAPABILITIES,
        )?);
        let browser = c
            .connect("http://localhost:4444")
            .await
            .expect("failed to connect to WebDriver");

        browser
            .goto("https://www.ntnu.no/studier/emner/TDT4120")
            .await?;
        let data = browser
            .issue_cmd(WebDriverCommand::Print(PrintParameters::default()))
            .await?;
        let str = data.as_str().unwrap();
        let pdf = base64::decode(str)?;

        fs::write("test.pdf", pdf)?;
        browser.close().await?;

        Result::Ok(())
        // Page.printToPDF
    }
}
