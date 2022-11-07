use fantoccini::wd::Capabilities;
use webdriver::command::{PrintParameters, WebDriverCommand};

const WEB_DRIVER_CAPABILITIES: &str = include_str!("WebDriverCapabilities.json");

pub async fn setup() -> Result<fantoccini::Client, anyhow::Error> {
    let mut builder = fantoccini::ClientBuilder::native();
    builder.capabilities(serde_json::from_str::<Capabilities>(
        WEB_DRIVER_CAPABILITIES,
    )?);

    Ok(builder
        .connect("http://localhost:4444")
        .await
        .expect("failed to connect to WebDriver"))
}

pub async fn print_page(browser: &fantoccini::Client, url: &str) -> Result<Vec<u8>, anyhow::Error> {
    browser.goto(url).await?;
    let data = browser
        .issue_cmd(WebDriverCommand::Print(PrintParameters::default()))
        .await?;
    Ok(base64::decode(data.as_str().unwrap())?)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use std::path::PathBuf;

    #[tokio::test]
    async fn test_print_pdf() -> Result<(), anyhow::Error> {
        let browser = setup().await?;
        let pdf = print_page(&browser, "https://www.ntnu.no/studier/emner/TDT4120").await?;

        let mut d = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        d.push("target/test_artifacts");
        fs::create_dir_all(&d)?;
        d.push("test.pdf");
        fs::write(d, pdf)?;
        browser.close().await?;

        Ok(())
    }
}
