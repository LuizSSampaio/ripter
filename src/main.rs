use clap::Parser;

use crate::{cli::Cli, files::Files};

mod cli;
mod crypter;
mod files;

fn main() {
    let cli = Cli::parse();

    let files = match Files::new(cli.recursive, cli.get_paths()) {
        Ok(files) => files,
        Err(e) => {
            println!("ERROR: {}", e);
            return;
        }
    };

    files.run(cli.get_decryption_key());
}
