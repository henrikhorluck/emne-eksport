use clap::Parser;
use openidconnect::{ClientId, ClientSecret};

use std::convert::Infallible;
use std::fs;
use std::path::PathBuf;

mod auth;
mod browser;
mod types;

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

    let access_token =
        auth::authenticate(config.client_id, config.client_secret, config.redirect_port).await?;

    let client = reqwest::Client::new();

    let emner: Vec<types::Emne> = client
        .get("https://groups-api.dataporten.no/groups/me/groups?type=fc:fs:emne") // TODO: this query-param doesn't work
        .bearer_auth(access_token.secret())
        .send()
        .await?
        .json()
        .await?;

    let browser = browser::setup().await?;

    fs::create_dir(&config.destination)?;

    for emne in emner.iter().filter(|e| e.emne_type == "fc:fs:emne") {
        let pdf = browser::print_page(&browser, &emne.uri()).await?;

        fs::write(
            config.destination.join(format!("{}.pdf", emne.emne_code())),
            pdf,
        )?;
    }

    browser.close().await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::CommandFactory;

    #[test]
    fn verify_cli() {
        Cli::command().debug_assert();
    }
}
