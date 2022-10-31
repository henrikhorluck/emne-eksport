#![deny(rust_2018_idioms)]
#![allow(dead_code)]

use anyhow::anyhow;
use chrono::prelude::*;
use chrono::DateTime;
use clap::{Arg, Command};
use fantoccini::wd::WebDriverCompatibleCommand;
use http::{Request, Response, StatusCode};
use hyper::service::service_fn;
use hyper::{Body, Server};

use log::debug;
use openidconnect::core::{CoreClient, CoreProviderMetadata, CoreResponseType};
use openidconnect::reqwest::async_http_client;
use openidconnect::{
    AccessTokenHash, AuthenticationFlow, AuthorizationCode, ClientId, ClientSecret, CsrfToken,
    IssuerUrl, Nonce, OAuth2TokenResponse, PkceCodeChallenge, RedirectUrl, Scope, TokenResponse,
};
use serde::Deserialize;
use std::convert::Infallible;
use std::env;
use std::fs;
use std::sync::mpsc;
use std::sync::{Arc, Mutex};
use std::time::Duration;
use thiserror::Error;
use tokio::sync::oneshot;
use tower::make::Shared;
use url::Url;

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

#[derive(Error, Debug)]
pub enum ParseError {
    #[error("Invalid request")]
    Invalid(#[from] anyhow::Error),
    #[error("Not found")]
    NotFound(),
}
async fn parse_request(
    req: Request<Body>,
) -> Result<(Response<Body>, AuthorizationCode, CsrfToken), ParseError> {
    let redirect_url = req.uri();
    if redirect_url.path() != "/" {
        return Err(ParseError::Invalid(anyhow!("Not Found")));
    }
    // FIXME: what is happening here
    let url = Url::parse(&format!("http://localhost{redirect_url}")).unwrap();

    let code_pair = url
        .query_pairs()
        .find(|pair| {
            let &(ref key, _) = pair;
            key == "code"
        })
        .ok_or_else(|| anyhow!("Invalid request"))?;

    let (_, value) = code_pair;
    let code = AuthorizationCode::new(value.into_owned());

    let state_pair = url
        .query_pairs()
        .find(|pair| {
            let &(ref key, _) = pair;
            key == "state"
        })
        .ok_or_else(|| anyhow!("Irrelevant request"))?;

    let (_, value) = state_pair;
    let state = CsrfToken::new(value.into_owned());

    Ok((
        Response::new("Go back to your terminal :)".into()),
        code,
        state,
    ))
}

fn cli() -> clap::Command {
    Command::new("emne-eksport")
        .version("0.1")
        .about("Eksporter emnebeskrivelser fra utdanning ved NTNU")
        .arg(
            Arg::new("destination")
                .help("Name of the folder to put the exported PDFs")
                .short('d')
                .required(true),
        )
        .arg(
            Arg::new("client_id")
                .help("OIDC Client ID, can be retrieved from https://dashboard.dataporten.no/. Alternatively set through the `FEIDE_CLIENT_ID` environment variable")
        )
        .arg(
            Arg::new("client_secret")
                .help("OIDC Client Secret, can be retrieved from https://dashboard.dataporten.no/ Alternatively set through the `FEIDE_CLIENT_SECRET` environment variable")
        )
        .arg(Arg::new("redirect-port")
            .help("Port of the redirection-URL, which you configured in https://dashboard.dataporten.no")
            .default_value("16453")
            .short('p')
        )
}

#[tokio::main]
pub async fn main() -> Result<(), anyhow::Error> {
    env_logger::init();
    let config = cli().get_matches();
    let folder_path = config
        .get_one::<String>("destination")
        .map(|s| s.as_str())
        .unwrap();

    let feide_client_id = ClientId::new(
        config
            .get_one::<String>("client_id")
            .map(|s| s.to_string())
            .unwrap_or_else(|| env::var("FEIDE_CLIENT_ID").expect("Could not find ClientId")),
    );
    let feide_client_secret = ClientSecret::new(
        config
            .get_one::<String>("client_secret")
            .map(|s| s.to_string())
            .unwrap_or_else(|| env::var("FEIDE_CLIENT_SECRET").expect("Could not find ClientId")),
    );
    let port: u16 = config
        .get_one::<String>("redirect-port")
        .map(|s| s.to_string())
        .unwrap()
        .parse()?;

    let provider_metadata = CoreProviderMetadata::discover_async(
        IssuerUrl::new("https://auth.dataporten.no".to_string())?,
        async_http_client,
    )
    .await?;

    let client = CoreClient::from_provider_metadata(
        provider_metadata,
        feide_client_id,
        Some(feide_client_secret),
    )
    .set_redirect_uri(
        RedirectUrl::new(format!("http://localhost:{}", port)).expect("Invalid redirect URL"),
    );

    let (pkce_challenge, pkce_verifier) = PkceCodeChallenge::new_random_sha256();
    let (authorize_url, csrf_state, nonce) = client
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

    // A very naive implementation of the redirect server.
    // TODO: this is quite ugly
    let (code_tx, code_rx) = mpsc::sync_channel::<AuthorizationCode>(1);
    let (state_tx, state_rx) = mpsc::sync_channel::<CsrfToken>(1);
    let (tx, rx) = oneshot::channel::<()>();

    let (tx_2, rx_2) = oneshot::channel::<oneshot::Sender<()>>();
    tx_2.send(tx).unwrap();
    // yes, I send the oneshot through a oneshot, since oneshot::Sender::send(self) consumes self,
    // and this was genuinely one of the easier ways to get a Owned reference into the request
    // handler
    let rx_mtx = Arc::new(Mutex::new(rx_2));
    let make_servce = Shared::new(service_fn(move |req| {
        let code_tx = code_tx.clone();
        let state_tx = state_tx.clone();
        let rx_mtx = rx_mtx.clone();

        async move {
            let res: Result<(Response<Body>, AuthorizationCode, CsrfToken), ParseError> =
                parse_request(req).await;

            let ok: Result<Response<Body>, Infallible> = Ok(match res {
                Ok(res) => {
                    code_tx.send(res.1).unwrap();
                    state_tx.send(res.2).unwrap();
                    let tx = rx_mtx.lock().unwrap().try_recv().unwrap();
                    let _ = tx.send(());
                    res.0
                }
                Err(e) => match e {
                    ParseError::Invalid(_) => Response::builder()
                        .status(StatusCode::BAD_REQUEST)
                        .body(Body::empty())
                        .unwrap(),
                    ParseError::NotFound() => Response::builder()
                        .status(StatusCode::NOT_FOUND)
                        .body(Body::empty())
                        .unwrap(),
                },
            });
            ok
        }
    }));
    let thread_handler = tokio::spawn(async move {
        let server = Server::bind(&([127, 0, 0, 1], port).into()).serve(make_servce);
        // Prepare some signal for when the server should start shutting down...
        let graceful = server.with_graceful_shutdown(async {
            rx.await.ok();
        });

        // Await the `server` receiving the signal...
        if let Err(e) = graceful.await {
            eprintln!("server error: {}", e);
        }
    });

    // And later, trigger the signal by calling `tx.send(())`.
    let code = code_rx
        .recv_timeout(Duration::from_secs(60))
        .expect("Didn't log in in time");
    let state = state_rx.recv().unwrap();
    debug!("Feide returned the following code:\n{}\n", code.secret());
    debug!(
        "Feide returned the following state:\n{} (expected `{}`)\n",
        state.secret(),
        csrf_state.secret()
    );

    // Exchange the code with a token.
    let token_response = client
        .exchange_code(code.clone())
        .set_pkce_verifier(pkce_verifier)
        .request_async(async_http_client)
        .await?;

    let id_token = token_response
        .id_token()
        .ok_or_else(|| anyhow!("Server did not return an ID token"))?;
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
    c.capabilities(serde_json::Map::from_iter(
        [(
            "goog:chromeOptions".to_string(),
            serde_json::json!({
                    "args": ["--headless"],
            }),
        )]
        .into_iter(),
    ));

    let browser = c
        .connect("http://localhost:4444")
        .await
        .expect("failed to connect to WebDriver");

    fs::create_dir(folder_path)?;

    for emne in emner.iter().filter(|e| e.emne_type == "fc:fs:emne") {
        let emne_kode = emne.id.split(':').nth(5).unwrap();
        let year = if let Some(not_after) = emne.membership.not_after {
            // not_after is set to ~14. August if it is spring, and 12. December if autumn
            if not_after.month() > Month::September as u32 {
                not_after.year()
            } else {
                not_after.year() - 1
            }
        } else {
            // current year
            let now = Utc::now();
            if now.month() > Month::August as u32 {
                now.year()
            } else {
                now.year() - 1
            }
        };
        let uri = format!(
            "https://www.ntnu.edu/studies/courses/{emne_kode}/{year}",
            emne_kode = emne_kode,
            year = year
        );

        browser.goto(&uri).await?;
        let data = browser.issue_cmd(ScreenShotCommand {}).await?;
        let pdf = base64::decode(data.as_str().unwrap())?;

        /*
        let title = tab
            .find_element("#course-details > h1:first-type-of")
            .map_err(|e| e.compat())?
            .get_attributes()
            .map_err(|e| e.compat())?
            .ok_or(anyhow!("Emne-hedaer hadde ikke atributter"))?;

        let english_name = title
            .get("textValue")
            .ok_or(anyhow!("Emne har ikke tittel"))?;
        */
        fs::write(format!("{}/{}.pdf", folder_path, emne_kode), pdf)?;
    }

    thread_handler.await?;
    Ok(())
}

// Could inline https://github.com/atroche/rust-headless-chrome/blob/61ce783806e5d75a03f731330edae6156bb0a2e0/src/types.rs#L78
// but not that much point in it
#[derive(Debug)]
struct ScreenShotCommand {}

impl WebDriverCompatibleCommand for ScreenShotCommand {
    /// See <https://w3c.github.io/webdriver/#print-page>
    fn endpoint(
        &self,
        base_url: &url::Url,
        session_id: std::option::Option<&str>,
    ) -> Result<url::Url, url::ParseError> {
        let base = { base_url.join(&format!("session/{}/", session_id.as_ref().unwrap()))? };
        base.join("print")
    }
    fn method_and_body(&self, _request_url: &url::Url) -> (http::Method, Option<String>) {
        // needs to be empty json object, not None
        (http::Method::POST, Some("{}".to_string()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn verify_cli() {
        cli().debug_assert();
    }

    #[tokio::test]
    async fn test_print_pdf() -> Result<(), anyhow::Error> {
        let mut c = fantoccini::ClientBuilder::native();
        c.capabilities(serde_json::Map::from_iter(std::iter::once((
            "goog:chromeOptions".to_string(),
            serde_json::json!({
                    "args": ["--headless"],
            }),
        ))));
        let browser = c
            .connect("http://localhost:4444")
            .await
            .expect("failed to connect to WebDriver");

        browser
            .goto("https://www.ntnu.no/studier/emner/TDT4120")
            .await?;
        let data = browser.issue_cmd(ScreenShotCommand {}).await?;
        let str = data.as_str().unwrap();
        let pdf = base64::decode(str)?;

        fs::write("test.pdf", pdf)?;
        browser.close().await?;

        Result::Ok(())
        // Page.printToPDF
    }
}
