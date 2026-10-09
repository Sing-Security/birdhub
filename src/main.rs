//! The headless entry point: arguments, then the core from `birdhub`'s
//! library — the docs for the relay itself live in `src/lib.rs`.
//!
//! Everything here is CLI shape: flag parsing for the three enrollment
//! subcommands, and the config-path-or-subcommand decision. The run modes
//! live in the library, so the console can drive the same core.

use birdhub::config::AppMode;
use birdhub::{ca, config, hub, identity, transport, Error, Result};
use std::ffi::OsString;

// region:    --- Entry point

#[tokio::main]
async fn main() -> Result<()> {
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("info")).init();

    let args: Vec<String> = std::env::args_os()
        .skip(1)
        .map(OsString::into_string)
        .collect::<std::result::Result<_, _>>()
        .map_err(|bad| Error::custom(format!("argument is not valid UTF-8: {:?}", bad)))?;

    match (
        args.first().map(String::as_str),
        args.get(1).map(String::as_str),
    ) {
        (None, _) => run("config.toml").await,
        (Some("-h" | "--help"), _) => {
            println!("{}", usage());
            Ok(())
        }
        (Some("ca"), Some("init")) => {
            reject_unknown(&args, &["--key", "--pub", "--id"])?;
            ca::cmd_init(
                &required_flag(&args, "--key")?,
                &required_flag(&args, "--pub")?,
                &flag(&args, "--id")?.unwrap_or_else(|| "fleet-ca".to_string()),
            )
        }
        (Some("ca"), Some("issue")) => {
            reject_unknown(&args, &["--ca", "--identity", "--days", "--out"])?;
            let days: u64 = required_flag(&args, "--days")?
                .parse()
                .map_err(|e| Error::custom(format!("--days must be a number: {}", e)))?;
            ca::cmd_issue(
                &required_flag(&args, "--ca")?,
                &required_flag(&args, "--identity")?,
                days,
                &required_flag(&args, "--out")?,
            )
        }
        (Some("identity"), Some("export")) => {
            reject_unknown(&args, &["--key", "--pub", "--name"])?;
            identity::cmd_export(
                &required_flag(&args, "--key")?,
                &required_flag(&args, "--pub")?,
                &flag(&args, "--name")?.unwrap_or_else(|| "birdhub".to_string()),
            )
        }
        (Some("ca"), _) | (Some("identity"), _) => {
            Err(Error::custom(format!("unknown subcommand\n\n{}", usage())))
        }
        // A bare argument that is not a subcommand is the config path. One
        // that starts with `-` is a flag nobody defined — most likely a
        // mistyped subcommand, and worth saying so rather than trying to
        // open a file named `--help`.
        (Some(flag), _) if flag.starts_with('-') => Err(Error::custom(format!(
            "unknown flag '{}'\n\n{}",
            flag,
            usage()
        ))),
        (Some(path), _) => run(path).await,
    }
}

/// Load a configuration and run it in its mode.
async fn run(path: &str) -> Result<()> {
    let config = config::AppConfig::load_from_file(path)?;
    // Before anything binds or reads a key: a misplaced section is a
    // configuration line to fix, not a runtime symptom to debug.
    config.validate()?;

    match config.app.mode {
        AppMode::Hub => {
            println!("birdhub starting in hub mode (config: {})", path);
            hub::start(path, config).await
        }
        AppMode::Client => {
            println!("birdhub starting in client mode (config: {})", path);
            transport::start(path, config).await
        }
    }
}

// endregion: --- Entry point

// region:    --- Arguments

/// Flags are hand-parsed for the same reason the HTTP client was: three
/// subcommands with a fixed flag set do not justify a dependency, and the
/// error text is better when it is ours.
fn flag(args: &[String], name: &str) -> Result<Option<String>> {
    match args.iter().position(|arg| arg == name) {
        None => Ok(None),
        Some(i) => args
            .get(i + 1)
            .cloned()
            .map(Some)
            .ok_or_else(|| Error::custom(format!("{} needs a value", name))),
    }
}

fn required_flag(args: &[String], name: &str) -> Result<String> {
    flag(args, name)?.ok_or_else(|| Error::custom(format!("missing {}\n\n{}", name, usage())))
}

/// Reject flags this subcommand does not define.
///
/// Without this a mistyped `--dyas` is simply absent, and "missing --days"
/// sends the reader looking for the wrong problem.
fn reject_unknown(args: &[String], known: &[&str]) -> Result<()> {
    for arg in args.iter().filter(|arg| arg.starts_with("--")) {
        if !known.contains(&arg.as_str()) {
            return Err(Error::custom(format!(
                "unknown flag '{}'\n\n{}",
                arg,
                usage()
            )));
        }
    }
    Ok(())
}

fn usage() -> &'static str {
    "birdhub — relay over Temper identities

Usage:
  birdhub [config.toml]                 run (default: config.toml)

  birdhub ca init --key CA.key --pub ca.pub [--id NAME]
      Generate the fleet CA. The key file is the fleet's whole trust root:
      keep it on this machine and nowhere else. `ca.pub` goes to every node.

  birdhub ca issue --ca CA.key --identity node.pub --days N --out node.cert
      Certify a node's exported public identity. Copy the certificate back to
      the node as its [identity] certificate.

  birdhub identity export --key identity.key --pub node.pub [--name NAME]
      Write this node's public keys for the CA. Run on the node. Generates
      `identity.key` if it does not exist yet; NAME (default `birdhub`) is
      used only in that case, and becomes the certificate's subject id."
}

// endregion: --- Arguments
