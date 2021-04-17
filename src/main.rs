#![deny(rust_2018_idioms)]

use anyhow::anyhow;
use chrono::prelude::*;
use chrono::DateTime;
use clap::{App, Arg};
use headless_chrome::Browser;
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
    let url = Url::parse(&("http://localhost".to_string() + &redirect_url.to_string())).unwrap();

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

#[tokio::main]
pub async fn main() -> Result<(), anyhow::Error> {
    env_logger::init();
    let config = App::new("emne-eksport")
        .version("0.1")
        .about("Eksporter emnebeskrivelser fra utdanning ved NTNU")
        .author("Henrik Hørlück Berg <henrik@horluck.no")
        .arg(
            Arg::with_name("destination")
                .help("Name of the folder to put the exported PDFs")
                .short("d")
                .takes_value(true)
                .required(true),
        )
        .arg(
            Arg::with_name("client_id")
                .help("OIDC Client ID, can be retrieved from https://dashboard.dataporten.no/. Alternatively set through the `FEIDE_CLIENT_ID` environment variable")
                .takes_value(true),
        )
        .arg(
            Arg::with_name("client_secret")
                .help("OIDC Client Secret, can be retrieved from https://dashboard.dataporten.no/ Alternatively set through the `FEIDE_CLIENT_SECRET` environment variable")
                .takes_value(true),
        )
        .arg(Arg::with_name("redirect-port")
            .help("Port of the redircetio URL, which you configured in https://dashboard.dataporten.no. Default value 16453")
            .default_value("16453")
            .short("p")
            .takes_value(true)
        )
        .get_matches();
    let folder_path = config.value_of("destination").unwrap();

    let feide_client_id = ClientId::new(
        config
            .value_of("client_id")
            .map(|s| s.to_string())
            .unwrap_or_else(|| env::var("FEIDE_CLIENT_ID").expect("Could not find ClientId")),
    );
    let feide_client_secret = ClientSecret::new(
        config
            .value_of("client_secret")
            .map(|s| s.to_string())
            .unwrap_or_else(|| env::var("FEIDE_CLIENT_SECRET").expect("Could not find ClientId")),
    );
    let port: u16 = config.value_of("redirect-port").unwrap().parse()?;

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

    let browser = Browser::default().map_err(|e| e.compat())?;

    let tab = browser.wait_for_initial_tab().map_err(|e| e.compat())?;
    fs::create_dir(folder_path.to_string())?;

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

        let pdf = tab
            .navigate_to(&uri)
            .map_err(|e| e.compat())?
            .wait_until_navigated()
            .map_err(|e| e.compat())?
            .print_to_pdf(None)
            .map_err(|e| e.compat())?;

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
