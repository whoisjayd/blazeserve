use super::ansi::{self, Style};
use crate::usage::{self, Decision, Settings};
use clap::{Args, Subcommand};

#[derive(Args, Debug)]
pub struct TelemetryArgs {
    #[command(subcommand)]
    action: Action,
}

#[derive(Subcommand, Debug)]
enum Action {
    /// Show whether analytics are sent, why, and your anonymous ID
    Status,
    /// Turn anonymous analytics on
    Enable,
    /// Turn anonymous analytics off and discard anything waiting to be sent
    Disable,
    /// Forget the saved choice and the anonymous ID; the notice shows again
    Reset,
    /// Print examples of what is sent, without sending anything
    Preview,
}

fn settings_path() -> Result<std::path::PathBuf, String> {
    usage::settings_path(&usage::process_env)
        .ok_or_else(|| "cannot locate a settings directory on this system".to_owned())
}

fn save(enabled: bool) -> Result<(), String> {
    let path = settings_path()?;
    let mut settings = usage::load_settings(&path)
        .ok()
        .flatten()
        .unwrap_or_default();
    settings = Settings {
        enabled,
        // Choosing either way shows that the user has read what is collected.
        notice_version: usage::NOTICE_VERSION,
        ..settings
    };
    usage::save_settings(&path, &settings)
        .map_err(|e| format!("cannot write {}: {e}", path.display()))
}

fn status() -> String {
    let env = usage::process_env;
    let (key, host) = (usage::build_time_key(), usage::build_time_host());
    let (decision, persisted) = usage::effective(&env, key, host);
    let mut rows = vec![(
        "Analytics",
        match decision {
            Decision::Enabled => "enabled".to_owned(),
            Decision::Disabled(_) => "disabled".to_owned(),
        },
    )];
    if let Decision::Disabled(reason) = decision {
        rows.push(("Reason", reason.why().to_owned()));
    }
    rows.push((
        "PostHog",
        if usage::target(&env, key, host).is_some() {
            "configured"
        } else {
            "not configured"
        }
        .to_owned(),
    ));
    if let Some(id) = persisted.and_then(|s| s.install_id) {
        rows.push(("Anonymous ID", id));
    }
    let waiting = usage::queued(&env);
    if waiting > 0 {
        rows.push(("Waiting", format!("{waiting} events not yet sent")));
    }
    if let Some(p) = usage::settings_path(&env) {
        rows.push(("Settings", crate::cli::util::friendly_path(&p)));
    }
    ansi::rows(Style::stdout(), &rows)
}

fn show_status() {
    let body = status();
    ansi::card("Usage analytics", &body, &body);
}

fn preview() -> Result<String, String> {
    let mut out = String::new();
    for event in usage::preview(&usage::process_env) {
        out.push_str(&serde_json::to_string_pretty(&event).map_err(|e| e.to_string())?);
        out.push('\n');
    }
    out.push_str(
        "\nNothing was sent. `blaze telemetry status` shows whether a real run would send.\n",
    );
    Ok(out)
}

pub fn run(args: TelemetryArgs) -> Result<u8, String> {
    match args.action {
        Action::Status => show_status(),
        Action::Enable => {
            save(true)?;
            show_status();
        }
        Action::Disable => {
            save(false)?;
            usage::clear_queue(&usage::process_env);
            show_status();
        }
        Action::Reset => {
            let path = settings_path()?;
            usage::reset_settings(&path)
                .map_err(|e| format!("cannot remove {}: {e}", path.display()))?;
            usage::clear_queue(&usage::process_env);
            anstream::println!(
                "Saved choice and anonymous ID removed. The notice will show again on the next run."
            );
        }
        Action::Preview => anstream::print!("{}", preview()?),
    }
    Ok(0)
}
