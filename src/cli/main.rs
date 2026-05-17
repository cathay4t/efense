// SPDX-License-Identifier: Apache-2.0

mod monitor;

use efence::EfenceError;

use self::monitor::CommandMonitor;

#[tokio::main]
async fn main() -> Result<(), EfenceError> {
    let mut cli_cmd = clap::Command::new("efctl")
        .about("efence CLI")
        .arg_required_else_help(true)
        .subcommand_required(true)
        .subcommand(CommandMonitor::new_cmd());
    let matches = cli_cmd.get_matches_mut();

    env_logger::init();

    if let Some(matches) = matches.subcommand_matches(CommandMonitor::CMD) {
        CommandMonitor::handle(matches).await
    } else {
        Ok(())
    }
}
