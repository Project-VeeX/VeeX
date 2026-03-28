#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Command {
    Run { config_path: String },
    Check { config_path: String },
    Version,
}

#[derive(Debug)]
pub struct CommandError(pub String);

impl std::fmt::Display for CommandError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for CommandError {}

pub fn parse_args<I>(args: I) -> Result<Command, CommandError>
where
    I: IntoIterator<Item = String>,
{
    let mut args = args.into_iter();
    let _program = args.next();

    let Some(command) = args.next() else {
        return Err(CommandError(usage()));
    };

    match command.as_str() {
        "run" => parse_config_path(args).map(|config_path| Command::Run { config_path }),
        "check" => parse_config_path(args).map(|config_path| Command::Check { config_path }),
        "version" => Ok(Command::Version),
        other => Err(CommandError(format!(
            "unknown command '{other}'\n{}",
            usage()
        ))),
    }
}

fn parse_config_path<I>(mut args: I) -> Result<String, CommandError>
where
    I: Iterator<Item = String>,
{
    let Some(flag) = args.next() else {
        return Err(CommandError(
            "missing required flag '-c <config-path>'".to_string(),
        ));
    };

    if flag != "-c" && flag != "--config" {
        return Err(CommandError(format!(
            "unexpected argument '{flag}', expected '-c <config-path>'"
        )));
    }

    let Some(config_path) = args.next() else {
        return Err(CommandError("missing config path after '-c'".to_string()));
    };

    if args.next().is_some() {
        return Err(CommandError(
            "too many arguments; expected only '-c <config-path>'".to_string(),
        ));
    }

    Ok(config_path)
}

fn usage() -> String {
    [
        "usage:",
        "  veex run -c <config-path>",
        "  veex check -c <config-path>",
        "  veex version",
    ]
    .join("\n")
}

#[cfg(test)]
mod tests {
    use super::{parse_args, Command};

    #[test]
    fn parses_run_command() {
        let args = vec![
            "veex".to_string(),
            "run".to_string(),
            "-c".to_string(),
            "config.json".to_string(),
        ];

        let command = parse_args(args).expect("command should parse");
        assert_eq!(
            command,
            Command::Run {
                config_path: "config.json".into()
            }
        );
    }

    #[test]
    fn rejects_missing_flag() {
        let args = vec!["veex".to_string(), "check".to_string()];
        let err = parse_args(args).expect_err("missing flag should fail");
        assert!(err.to_string().contains("missing required flag"));
    }
}
