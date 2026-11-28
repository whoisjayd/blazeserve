//! `blaze info URL`: what a download of this address would get, without downloading it.

use clap::Args;
use serde::Serialize;
use ureq::http::{Response, StatusCode};

use super::download::default_destination;
use super::error::TransferError;
use super::filename::suggested_name;
use super::http::{agent, basic_header, describe_error, header, http_failure, http_url};
use super::limits::{self, TimeoutArgs};
use super::segmented;
use crate::cli::ansi::{self, Style};
use crate::cli::util::human_size;

#[derive(Args, Debug)]
pub struct InfoArgs {
    /// The address to ask about
    pub url: String,
    /// Load USER:PASS from an environment variable
    #[arg(long, value_name = "ENVVAR", conflicts_with = "auth")]
    pub auth_env: Option<String>,
    /// USER:PASS. Visible to other users of this computer; prefer --auth-env
    #[arg(long, value_name = "USER:PASS")]
    pub auth: Option<String>,
    /// Print JSON
    #[arg(long)]
    pub json: bool,
    #[command(flatten)]
    pub timeouts: TimeoutArgs,
}

#[derive(Debug, Serialize)]
struct About {
    name: String,
    size: Option<u64>,
    content_type: Option<String>,
    resume: bool,
    /// Whether `blaze get` would use several connections.
    parts: bool,
    why_not: Option<&'static str>,
    etag: Option<String>,
    last_modified: Option<String>,
    server: Option<String>,
}

fn ask(
    agent: &ureq::Agent,
    url: &str,
    auth: Option<&str>,
    ranged: bool,
) -> Result<Response<ureq::Body>, TransferError> {
    let sent = if ranged {
        let mut req = agent.get(url).header("Range", "bytes=0-0");
        if let Some(a) = auth {
            req = req.header("Authorization", a);
        }
        limits::bound(req).call()
    } else {
        let mut req = agent.head(url);
        if let Some(a) = auth {
            req = req.header("Authorization", a);
        }
        limits::bound(req).call()
    };
    sent.map_err(|e| TransferError::Network(describe_error(&e)))
}

/// Some links answer a download but not a `HEAD`, so one byte is asked for instead.
fn look(url: &str, auth: Option<&str>) -> Result<About, TransferError> {
    let agent = agent();
    let mut answer = ask(&agent, url, auth, false)?;
    let mut why_not = segmented::assess(&answer).err();
    if answer.status() != StatusCode::OK {
        answer = ask(&agent, url, auth, true)?;
        if !matches!(answer.status().as_u16(), 200 | 206) {
            return Err(http_failure(answer.status().as_u16(), false));
        }
        why_not = Some(Some("the server does not answer a size check (HEAD)"));
    }
    let partial = answer.status() == StatusCode::PARTIAL_CONTENT;
    // A one-byte answer states the whole size after the slash of Content-Range.
    let size = if partial {
        header(&answer, "content-range")
            .and_then(|v| v.rsplit('/').next().and_then(|n| n.parse().ok()))
    } else {
        header(&answer, "content-length").and_then(|v| v.parse().ok())
    };
    let name = match header(&answer, "content-disposition").and_then(|v| suggested_name(&v)) {
        Some(name) => name,
        None => default_destination(url)?.display().to_string(),
    };
    Ok(About {
        name,
        size,
        content_type: header(&answer, "content-type"),
        resume: partial
            || header(&answer, "accept-ranges")
                .is_some_and(|v| v.to_ascii_lowercase().contains("bytes")),
        parts: why_not.is_none(),
        why_not: why_not.flatten(),
        etag: header(&answer, "etag"),
        last_modified: header(&answer, "last-modified"),
        server: header(&answer, "server"),
    })
}

fn rows(about: &About, style: Style) -> String {
    let unknown = || "unknown".to_owned();
    let size = about
        .size
        .map_or_else(unknown, |n| format!("{} ({n} bytes)", human_size(n)));
    let parts = match (about.parts, about.why_not) {
        (true, _) => "yes: blaze get uses several connections".to_owned(),
        (false, Some(why)) => format!("no: {why}"),
        (false, None) => "no: too small to need them".to_owned(),
    };
    let mut rows = vec![
        ("File", about.name.clone()),
        ("Size", size),
        ("Type", about.content_type.clone().unwrap_or_else(unknown)),
        ("Resume", if about.resume { "yes" } else { "no" }.to_owned()),
        ("In parts", parts),
    ];
    if let Some(etag) = &about.etag {
        rows.push(("ETag", etag.clone()));
    }
    if let Some(changed) = &about.last_modified {
        rows.push(("Modified", changed.clone()));
    }
    if let Some(server) = &about.server {
        rows.push(("Server", server.clone()));
    }
    ansi::rows(style, &rows)
}

pub fn info(args: InfoArgs) -> Result<u8, TransferError> {
    http_url(&args.url)?;
    let auth = basic_header(args.auth.as_deref(), args.auth_env.as_deref())?;
    limits::install(&args.timeouts);
    let about = look(&args.url, auth.as_deref())?;
    if args.json {
        let text = serde_json::to_string_pretty(&about)
            .map_err(|e| TransferError::Io(format!("cannot write JSON: {e}")))?;
        anstream::println!("{text}");
        return Ok(0);
    }
    let body = rows(&about, Style::stdout());
    ansi::card("About this download", &body, &body);
    Ok(0)
}
