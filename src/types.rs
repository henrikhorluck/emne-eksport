use chrono::prelude::*;
use chrono::DateTime;
use serde::Deserialize;

#[derive(Debug, Deserialize)]
pub struct Emne {
    pub id: String,
    #[serde(rename = "type")]
    pub emne_type: String,
    pub parent: String,
    pub membership: Membership,
    #[serde(rename = "displayName")]
    pub display_name: String,
}

impl Emne {
    pub fn year_taken(&self) -> i32 {
        let now = Utc::now();
        // not_after is set to ~14. August if it is spring, and 12. December if autumn
        match self.membership.not_after {
            Some(y) if y.month() > Month::September as u32 => y.year(),
            Some(y) => y.year() - 1,
            None if now.month() > Month::August as u32 => now.year(),
            None => now.year() - 1,
        }
    }

    pub fn emne_code(&self) -> &str {
        self.id.split(':').nth(5).unwrap()
    }

    pub fn uri(&self) -> String {
        // TODO: support 1. localization, 2. different universities by reading from the id
        let emne_code = self.emne_code();
        let year_taken = self.year_taken();
        format!("https://www.ntnu.edu/studies/courses/{emne_code}/{year_taken}")
    }
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Membership {
    pub basic: String,
    pub fsroles: Vec<String>,
    pub active: bool,
    pub not_after: Option<DateTime<Utc>>,
    pub display_name: String,
    pub subject_relations: Option<String>,
}
