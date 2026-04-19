#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Command {
    Run { config_path: String, verbose: bool },
    Check { config_path: String, verbose: bool },
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
        "run" => parse_config_options(args).map(|(config_path, verbose)| Command::Run {
            config_path,
            verbose,
        }),
        "check" => parse_config_options(args).map(|(config_path, verbose)| Command::Check {
            config_path,
            verbose,
        }),
        "version" => Ok(Command::Version),
        other => Err(CommandError(format!(
            "unknown command '{other}'\n{}",
            usage()
        ))),
    }
}

fn parse_config_options<I>(args: I) -> Result<(String, bool), CommandError>
where
    I: Iterator<Item = String>,
{
    let mut config_path = None;
    let mut verbose = false;
    let mut args = args.peekable();

    while let Some(arg) = args.next() {
        match arg.as_str() {
            "-c" | "--config" => {
                let Some(path) = args.next() else {
                    return Err(CommandError("missing config path after '-c'".to_string()));
                };
                if config_path.replace(path).is_some() {
                    return Err(CommandError(
                        "duplicate config flag; expected only one '-c <config-path>'".to_string(),
                    ));
                }
            }
            "--verbose" => {
                verbose = true;
            }
            other => {
                return Err(CommandError(format!(
                    "unexpected argument '{other}', expected '--verbose' or '-c <config-path>'"
                )));
            }
        }
    }

    let Some(config_path) = config_path else {
        return Err(CommandError(
            "missing required flag '-c <config-path>'".to_string(),
        ));
    };

    Ok((config_path, verbose))
}

fn usage() -> String {
    [
        "usage:",
        "  veex run [--verbose] -c <config-path>",
        "  veex check [--verbose] -c <config-path>",
        "  veex version",
    ]
    .join("\n")
}

#[cfg(test)]
mod tests {
    use super::{Command, parse_args};

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
                config_path: "config.json".into(),
                verbose: false,
            }
        );
    }

    #[test]
    fn parses_check_command_with_verbose_flag() {
        let args = vec![
            "veex".to_string(),
            "check".to_string(),
            "--verbose".to_string(),
            "-c".to_string(),
            "config.json".to_string(),
        ];

        let command = parse_args(args).expect("command should parse");
        assert_eq!(
            command,
            Command::Check {
                config_path: "config.json".into(),
                verbose: true,
            }
        );
    }

    #[test]
    fn parses_run_command_with_verbose_flag() {
        let args = vec![
            "veex".to_string(),
            "run".to_string(),
            "--verbose".to_string(),
            "-c".to_string(),
            "config.json".to_string(),
        ];

        let command = parse_args(args).expect("command should parse");
        assert_eq!(
            command,
            Command::Run {
                config_path: "config.json".into(),
                verbose: true,
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
