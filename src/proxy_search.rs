//! Provider-neutral adapters for structured search APIs.
//!
//! Search providers return API data only; this module does not fetch or parse
//! search-result HTML. Provider names in [`SearchResult::provider`] are stable
//! identifiers suitable for retaining result provenance in callers.

use std::{collections::HashSet, str::FromStr, time::Duration};

use anyhow::{anyhow, bail, Context, Result};
use reqwest::{header, Client, Response, StatusCode};
use serde::Deserialize;
use url::Url;

const MAX_RESULTS: usize = 50;
const BRAVE_MAX_RESULTS: usize = 20;
const YANDEX_MAX_GROUPS: usize = 20;
const GITHUB_API_VERSION: &str = "2022-11-28";
const USER_AGENT: &str = "ProxySift/0.1 (search adapter)";

/// Google, Yandex, Bing, and DuckDuckGo are served through SerpApi.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum SearchProvider {
    Google,
    Yandex,
    Bing,
    DuckDuckGo,
    GitHubCode,
    Brave,
}

impl SearchProvider {
    /// Stable provider identifier stored with each result.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Google => "google",
            Self::Yandex => "yandex",
            Self::Bing => "bing",
            Self::DuckDuckGo => "duckduckgo",
            Self::GitHubCode => "github",
            Self::Brave => "brave",
        }
    }
}

impl std::fmt::Display for SearchProvider {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(self.as_str())
    }
}

impl FromStr for SearchProvider {
    type Err = String;

    fn from_str(value: &str) -> std::result::Result<Self, Self::Err> {
        match value.trim().to_ascii_lowercase().as_str() {
            "google" => Ok(Self::Google),
            "yandex" => Ok(Self::Yandex),
            "bing" => Ok(Self::Bing),
            "duckduckgo" | "duck-duck-go" => Ok(Self::DuckDuckGo),
            "github" | "github-code" | "github_code" => Ok(Self::GitHubCode),
            "brave" => Ok(Self::Brave),
            _ => Err(format!(
                "unsupported search provider '{value}'; choose google, yandex, bing, duckduckgo, github, or brave"
            )),
        }
    }
}

/// Credentials for the supported providers.
///
/// Google, Yandex, Bing, and DuckDuckGo share one SerpApi key. GitHub code
/// search requires a personal access token; Brave uses its Search API token.
#[derive(Clone, Default)]
pub struct SearchCredentials {
    pub serpapi_api_key: Option<String>,
    pub github_token: Option<String>,
    pub brave_api_key: Option<String>,
}

/// Normalized search hit. `provider` identifies the API that returned the hit.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SearchResult {
    pub provider: String,
    pub title: String,
    pub url: String,
    pub snippet: String,
}

/// Search one provider and return at most `max_results` normalized hits.
///
/// `max_results` must be in `1..=50`. Providers with lower documented
/// per-request limits are capped accordingly. `timeout` applies to the entire
/// HTTP request, including response-body reading.
pub async fn search(
    provider: SearchProvider,
    query: &str,
    credentials: &SearchCredentials,
    max_results: usize,
    timeout: Duration,
) -> Result<Vec<SearchResult>> {
    let query = query.trim();
    if query.is_empty() {
        bail!("search query must not be empty");
    }
    if max_results == 0 || max_results > MAX_RESULTS {
        bail!("max_results must be between 1 and {MAX_RESULTS}");
    }
    if timeout.is_zero() {
        bail!("search timeout must be greater than zero");
    }

    let client = Client::builder()
        .timeout(timeout)
        .user_agent(USER_AGENT)
        .build()
        .context("could not create the search HTTP client")?;

    let results = match provider {
        SearchProvider::Google
        | SearchProvider::Yandex
        | SearchProvider::Bing
        | SearchProvider::DuckDuckGo => {
            search_serpapi(&client, provider, query, credentials, max_results).await?
        }
        SearchProvider::GitHubCode => {
            search_github(&client, query, credentials, max_results).await?
        }
        SearchProvider::Brave => {
            search_brave(&client, query, credentials, max_results).await?
        }
    };
    Ok(deduplicate_urls(provider, results, max_results))
}

async fn search_serpapi(
    client: &Client,
    provider: SearchProvider,
    query: &str,
    credentials: &SearchCredentials,
    max_results: usize,
) -> Result<Vec<SearchResult>> {
    let key = required_credential(
        credentials.serpapi_api_key.as_deref(),
        "SerpApi",
        "set SearchCredentials::serpapi_api_key to a SerpApi key (shared by Google, Yandex, Bing, and DuckDuckGo)",
    )?;
    let mut request = client.get("https://serpapi.com/search.json").query(&[
        ("engine", provider.as_str()),
        ("api_key", key),
    ]);
    request = match provider {
        SearchProvider::Google => request
            .query(&[("q", query), ("num", &max_results.min(MAX_RESULTS).to_string())]),
        SearchProvider::Yandex => request.query(&[
            ("text", query),
            (
                "groups_on_page",
                &max_results.min(YANDEX_MAX_GROUPS).to_string(),
            ),
        ]),
        SearchProvider::Bing | SearchProvider::DuckDuckGo => request.query(&[("q", query)]),
        _ => unreachable!("only public web search engines use SerpApi"),
    };
    let response = send(request, provider).await?;
    let payload: SerpApiResponse = decode_json(response, provider).await?;
    if let Some(error) = payload.error.filter(|message| !message.trim().is_empty()) {
        bail!("{provider} search via SerpApi failed: {error}; check the query and SerpApi account quota");
    }
    Ok(payload
        .organic_results
        .unwrap_or_default()
        .into_iter()
        .map(|hit| SearchResult {
            provider: provider.as_str().to_owned(),
            title: hit.title.unwrap_or_default(),
            url: hit.link.unwrap_or_default(),
            snippet: hit.snippet.unwrap_or_default(),
        })
        .collect())
}

async fn search_github(
    client: &Client,
    query: &str,
    credentials: &SearchCredentials,
    max_results: usize,
) -> Result<Vec<SearchResult>> {
    let token = required_credential(
        credentials.github_token.as_deref(),
        "GitHub code search",
        "set SearchCredentials::github_token to a GitHub personal access token",
    )?;
    let response = client
        .get("https://api.github.com/search/code")
        .query(&[("q", query), ("per_page", &max_results.to_string())])
        .bearer_auth(token)
        .header(header::ACCEPT, "application/vnd.github.text-match+json")
        .header("X-GitHub-Api-Version", GITHUB_API_VERSION)
        .send()
        .await
        .map_err(|error| request_error(SearchProvider::GitHubCode, error))?;
    let payload: GitHubCodeResponse = decode_json(response, SearchProvider::GitHubCode).await?;
    Ok(payload
        .items
        .into_iter()
        .map(|hit| SearchResult {
            provider: SearchProvider::GitHubCode.as_str().to_owned(),
            title: hit.name.unwrap_or_else(|| hit.path.clone()),
            url: hit.html_url.unwrap_or_default(),
            snippet: hit
                .text_matches
                .unwrap_or_default()
                .into_iter()
                .map(|matched| matched.fragment)
                .filter(|fragment| !fragment.is_empty())
                .collect::<Vec<_>>()
                .join(" … "),
        })
        .collect())
}

async fn search_brave(
    client: &Client,
    query: &str,
    credentials: &SearchCredentials,
    max_results: usize,
) -> Result<Vec<SearchResult>> {
    let token = required_credential(
        credentials.brave_api_key.as_deref(),
        "Brave Search",
        "set SearchCredentials::brave_api_key to a Brave Search API subscription token",
    )?;
    let response = client
        .get("https://api.search.brave.com/res/v1/web/search")
        .query(&[("q", query), ("count", &max_results.min(BRAVE_MAX_RESULTS).to_string())])
        .header(header::ACCEPT, "application/json")
        .header("X-Subscription-Token", token)
        .send()
        .await
        .map_err(|error| request_error(SearchProvider::Brave, error))?;
    let payload: BraveResponse = decode_json(response, SearchProvider::Brave).await?;
    Ok(payload
        .web
        .and_then(|web| web.results)
        .unwrap_or_default()
        .into_iter()
        .map(|hit| SearchResult {
            provider: SearchProvider::Brave.as_str().to_owned(),
            title: hit.title.unwrap_or_default(),
            url: hit.url.unwrap_or_default(),
            snippet: hit.description.unwrap_or_default(),
        })
        .collect())
}

fn required_credential<'a>(
    value: Option<&'a str>,
    provider_name: &str,
    guidance: &str,
) -> Result<&'a str> {
    value
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .ok_or_else(|| anyhow!("{provider_name} credentials are missing; {guidance}"))
}

async fn send(request: reqwest::RequestBuilder, provider: SearchProvider) -> Result<Response> {
    request
        .header(header::ACCEPT, "application/json")
        .send()
        .await
        .map_err(|error| request_error(provider, error))
}

fn request_error(provider: SearchProvider, error: reqwest::Error) -> anyhow::Error {
    if error.is_timeout() {
        anyhow!("{provider} search timed out; increase the timeout or retry")
    } else if error.is_connect() {
        anyhow!("could not connect to the {provider} search API; check network access and retry")
    } else {
        anyhow!("{provider} search request failed: {}", error.without_url())
    }
}

async fn decode_json<T: for<'de> Deserialize<'de>>(
    response: Response,
    provider: SearchProvider,
) -> Result<T> {
    let status = response.status();
    let body = response
        .text()
        .await
        .map_err(|error| request_error(provider, error))?;
    if !status.is_success() {
        let guidance = match status {
            StatusCode::UNAUTHORIZED | StatusCode::FORBIDDEN => {
                "check the API key/token and its required access"
            }
            StatusCode::TOO_MANY_REQUESTS => "the provider rate limit or quota was reached; retry later or check the account plan",
            StatusCode::NOT_FOUND if provider == SearchProvider::GitHubCode => {
                "GitHub code search requires an authenticated request; check the token"
            }
            _ => "check the provider API status and request parameters",
        };
        let detail = response_error_detail(&body);
        bail!("{provider} search API returned HTTP {status}; {guidance}. Provider detail: {detail}");
    }
    serde_json::from_str(&body)
        .with_context(|| format!("{provider} search API returned invalid JSON"))
}

fn response_error_detail(body: &str) -> String {
    let detail = serde_json::from_str::<serde_json::Value>(body)
        .ok()
        .and_then(|json| {
            json.get("message")
                .or_else(|| json.get("error"))
                .and_then(serde_json::Value::as_str)
                .map(str::to_owned)
        })
        .unwrap_or_else(|| body.trim().to_owned());
    let mut chars = detail.chars();
    let shortened: String = chars.by_ref().take(300).collect();
    if chars.next().is_some() {
        format!("{shortened}…")
    } else if shortened.is_empty() {
        "empty response body".to_owned()
    } else {
        shortened
    }
}

fn deduplicate_urls(
    provider: SearchProvider,
    results: Vec<SearchResult>,
    max_results: usize,
) -> Vec<SearchResult> {
    let mut seen = HashSet::with_capacity(results.len());
    results
        .into_iter()
        .filter_map(|mut result| {
            if result.title.trim().is_empty() {
                return None;
            }
            let key = canonical_url(&result.url)?;
            if !seen.insert(key) {
                return None;
            }
            result.provider = provider.as_str().to_owned();
            Some(result)
        })
        .take(max_results)
        .collect()
}

fn canonical_url(value: &str) -> Option<String> {
    let mut url = Url::parse(value.trim()).ok()?;
    if !matches!(url.scheme(), "http" | "https") || url.host_str().is_none() {
        return None;
    }
    url.set_fragment(None);
    Some(url.to_string())
}

#[derive(Deserialize)]
struct SerpApiResponse {
    #[serde(default)]
    organic_results: Option<Vec<SerpApiHit>>,
    #[serde(default)]
    error: Option<String>,
}

#[derive(Deserialize)]
struct SerpApiHit {
    title: Option<String>,
    link: Option<String>,
    snippet: Option<String>,
}

#[derive(Deserialize)]
struct GitHubCodeResponse {
    #[serde(default)]
    items: Vec<GitHubCodeHit>,
}

#[derive(Deserialize)]
struct GitHubCodeHit {
    name: Option<String>,
    path: String,
    html_url: Option<String>,
    text_matches: Option<Vec<GitHubTextMatch>>,
}

#[derive(Deserialize)]
struct GitHubTextMatch {
    fragment: String,
}

#[derive(Deserialize)]
struct BraveResponse {
    web: Option<BraveWebResults>,
}

#[derive(Deserialize)]
struct BraveWebResults {
    results: Option<Vec<BraveHit>>,
}

#[derive(Deserialize)]
struct BraveHit {
    title: Option<String>,
    url: Option<String>,
    description: Option<String>,
}
