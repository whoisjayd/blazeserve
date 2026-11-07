use super::ansi::{self, Style};
use crate::usage::{self, Command, Decision, Features, Settings, StopStats};
use clap::{Args, Subcommand};
use std::process::ExitCode;
use std::time::Duration;

#[derive(Args, Debug)]
pub struct TelemetryArgs {
    #[command(subcommand)]
    action: Action,
}

#[derive(Subcommand, Debug)]
enum Action {
    /// Show whether usage statistics are sent, and why
    Status,
    /// Turn usage statistics on
    Enable,
    /// Turn usage statistics off
    Disable,
    /// Forget the saved choice and show the notice again on the next run
    Reset,
    /// Print the exact payloads a run would send, without sending anything
    Preview,
}

fn settings_path() -> Result<std::path::PathBuf, String> {
    usage::settings_path(&usage::process_env)
        .ok_or_else(|| "cannot locate a settings directory on this system".to_owned())
}

fn save(enabled: bool) -> Result<(), String> {
    let path = settings_path()?;
    usage::save_settings(
        &path,
        Settings {
            enabled,
            notice_shown: true,
        },
    )
    .map_err(|e| format!("cannot write {}: {e}", path.display()))
}

fn status() -> String {
    let style = Style::stdout();
    let build = usage::build_time_url();
    let (decision, _) = usage::effective(&usage::process_env, build);
    let relay = usage::relay_url(&usage::process_env, build).is_some();
    let mut rows = vec![(
        "Telemetry",
        match decision {
            Decision::Enabled => "enabled".to_owned(),
            Decision::Disabled(_) => "disabled".to_owned(),
        },
    )];
    if let Decision::Disabled(reason) = decision {
        rows.push(("Reason", reason.why().to_owned()));
    }
    rows.push((
        "Relay",
        if relay {
            "configured"
        } else {
            "not configured"
        }
        .to_owned(),
    ));
    if let Some(p) = usage::settings_path(&usage::process_env) {
        rows.push(("Settings", p.display().to_string()));
    }
    ansi::rows(style, &rows)
}

fn preview() -> Result<String, String> {
    let env = usage::process_env;
    let features = Features {
        listing: true,
        ..Features::default()
    };
    let start = usage::start_event(&env, Command::Serve, features);
    let stop = usage::stop_event(
        &env,
        Command::Serve,
        features,
        Duration::from_secs(3600),
        StopStats {
            requests_total: 120,
            bytes_sent: 5 << 30,
            errors_total: 0,
        },
    );
    let pretty = |e: &usage::Event| serde_json::to_string_pretty(e).map_err(|e| e.to_string());
    Ok(format!(
        "Start event:\n{}\n\nStop event:\n{}\n\nNothing was sent. Run `blaze telemetry status` to see whether a real run would send these.\n",
        pretty(&start)?,
        pretty(&stop)?
    ))
}

pub fn run(args: TelemetryArgs) -> Result<ExitCode, String> {
    match args.action {
        Action::Status => print!("{}", status()),
        Action::Enable => {
            save(true)?;
            print!("{}", status());
        }
        Action::Disable => {
            save(false)?;
            print!("{}", status());
        }
        Action::Reset => {
            let path = settings_path()?;
            usage::reset_settings(&path)
                .map_err(|e| format!("cannot remove {}: {e}", path.display()))?;
            println!("Saved choice removed. The notice will show again on the next run.");
        }
        Action::Preview => print!("{}", preview()?),
    }
    Ok(ExitCode::SUCCESS)
}
