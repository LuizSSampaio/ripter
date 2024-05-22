use clap::Parser;

#[derive(Parser)]
#[command(version = "0.1.0", about = "Simple encrypter and decrypter", long_about = None)]
pub struct Cli {
    /// Decryption key
    #[arg(short, long)]
    decrypt: Option<String>,

    /// Encrypt or decrypt folders
    #[arg(short, long)]
    pub recursive: bool,

    /// Files or Folders(if recursive) to be encrypted ou decrypted
    files: Option<Vec<String>>,
}

impl Cli {
    pub fn get_paths(&self) -> Vec<String> {
        match &self.files {
            Some(files) => files.to_owned(),
            None => Vec::new(),
        }
    }

    pub fn get_decryption_key(&self) -> String {
        match &self.decrypt {
            Some(key) => key.to_owned(),
            None => String::new(),
        }
    }
}
