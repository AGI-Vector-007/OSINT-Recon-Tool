use reqwest::{Client, StatusCode};
use serde_json::Value;
use clap::{Arg, Command};
use tokio;
use openai_rs::{Client as OpenAIClient, ChatMessage};
use dotenv::dotenv;
use std::env;
use thiserror::Error;
use anyhow::{Result, Context};
use tokio::time::{sleep, Duration};
use std::fs::File;
use std::io::Write;

#[derive(Error, Debug)]
enum OsintError {
    #[error("HTTP request failed: {0}")]
    HttpRequest(#[from] reqwest::Error),
    #[error("Invalid OSINT type")] 
    InvalidType,
    #[error("Missing API Key: {0}")]
    MissingApiKey(String),
}

const RETRY_ATTEMPTS: u8 = 3;
const RETRY_DELAY: Duration = Duration::from_secs(5);

async fn fetch_with_retries(url: &str, user_agent: Option<&str>) -> Result<String, OsintError> {
    let client = Client::new();
    for attempt in 0..RETRY_ATTEMPTS {
        let mut request = client.get(url);
        if let Some(ua) = user_agent {
            request = request.header("User-Agent", ua);
        }
        
        match request.send().await {
            Ok(response) if response.status().is_success() => return Ok(response.text().await?),
            Ok(response) if response.status() == StatusCode::TOO_MANY_REQUESTS => {
                eprintln!("Rate limited! Retrying in {} seconds...", RETRY_DELAY.as_secs());
                sleep(RETRY_DELAY).await;
            }
            Ok(response) => return Err(OsintError::HttpRequest(reqwest::Error::new(response.status(), "API Error"))),
            Err(err) => return Err(OsintError::HttpRequest(err)),
        }
    }
    Err(OsintError::HttpRequest(reqwest::Error::new(StatusCode::BAD_REQUEST, "Max retries exceeded")))
}

async fn fetch_whois(domain: &str) -> Result<Value, OsintError> {
    let url = format!("https://api.whois.vu/?q={}", domain);
    let response = fetch_with_retries(&url, None).await?;
    serde_json::from_str(&response).map_err(|_| OsintError::HttpRequest(reqwest::Error::new(StatusCode::BAD_REQUEST, "Failed to parse JSON")))
}

async fn fetch_shodan(ip: &str) -> Result<Value, OsintError> {
    let shodan_key = env::var("SHODAN_API_KEY").map_err(|_| OsintError::MissingApiKey("SHODAN_API_KEY".to_string()))?;
    let url = format!("https://api.shodan.io/shodan/host/{}?key={}", ip, shodan_key);
    let response = fetch_with_retries(&url, None).await?;
    serde_json::from_str(&response).map_err(|_| OsintError::HttpRequest(reqwest::Error::new(StatusCode::BAD_REQUEST, "Failed to parse JSON")))
}

async fn fetch_hibp(email: &str) -> Result<Value, OsintError> {
    let url = format!("https://haveibeenpwned.com/api/v3/breachedaccount/{}", email);
    let response = fetch_with_retries(&url, Some("Rust-OSINT-Tool/1.0")).await?;
    serde_json::from_str(&response).map_err(|_| OsintError::HttpRequest(reqwest::Error::new(StatusCode::BAD_REQUEST, "Failed to parse JSON")))
}

fn save_report(target: &str, data: &Value) -> Result<(), std::io::Error> {
    let filename = format!("{}_osint_report.json", target);
    let mut file = File::create(&filename)?;
    file.write_all(data.to_string().as_bytes())?;
    println!("Report saved to: {}", filename);
    Ok(())
}

async fn analyze_with_chatgpt(api_key: &str, data: &Value) -> Result<String, OsintError> {
    let client = OpenAIClient::new(api_key);
    let messages = vec![
        ChatMessage::system("You are a cybersecurity expert."),
        ChatMessage::user(&format!("Analyze this OSINT data: {}", data)),
    ];
    let response = client.chat(messages).await.unwrap();
    Ok(response)
}

#[tokio::main]
async fn main() -> Result<(), OsintError> {
    dotenv().ok(); // Load environment variables from .env file
    let matches = Command::new("OSINT Recon Tool")
        .version("1.0")
        .author("Vector")
        .about("Performs OSINT reconnaissance using Rust and AI analysis")
        .arg(Arg::new("target").help("Target domain/IP/email").required(true))
        .arg(Arg::new("type").help("Type: whois/shodan/hibp").required(true))
        .get_matches();
    
    let target = matches.get_one::<String>("target").unwrap();
    let recon_type = matches.get_one::<String>("type").unwrap();
    let openai_api_key = env::var("OPENAI_API_KEY").map_err(|_| OsintError::MissingApiKey("OPENAI_API_KEY".to_string()))?;
    
    let osint_data = match recon_type.as_str() {
        "whois" => fetch_whois(target).await,
        "shodan" => fetch_shodan(target).await,
        "hibp" => fetch_hibp(target).await,
        _ => Err(OsintError::InvalidType),
    };
    
    match osint_data {
        Ok(data) => {
            println!("Raw OSINT Data: \n{}", data);
            save_report(target, &data)?;
            match analyze_with_chatgpt(&openai_api_key, &data).await {
                Ok(analysis) => println!("ChatGPT Analysis: \n{}", analysis),
                Err(err) => eprintln!("Error analyzing data with ChatGPT: {}", err),
            }
        },
        Err(err) => eprintln!("Error fetching OSINT data: {}", err),
    }
    Ok(())
}

