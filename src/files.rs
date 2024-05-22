use core::fmt;
use std::{fmt::Debug, fs, path::PathBuf};

use crate::crypter::Crypter;

pub struct Files {
    is_recursive: bool,
    paths: Vec<String>,
}

impl Files {
    pub fn new(is_recursive: bool, files: Vec<String>) -> Result<Self, FilesError> {
        if files.is_empty() {
            return Err(FilesError::NoFiles);
        }

        for file in &files {
            let file_path = PathBuf::from(file);
            if file_path.is_dir() && !is_recursive {
                return Err(FilesError::NoRecursiveFolders);
            } else if !file_path.is_file() && !file_path.is_dir() {
                return Err(FilesError::FileNotFound);
            }
        }

        Ok(Self {
            is_recursive,
            paths: files,
        })
    }

    pub fn run(&self, key: String) {
        let mut crypter = Crypter::new(key);

        for path in &self.paths {
            let file = PathBuf::from(path);

            if file.is_dir() && self.is_recursive {
                let entries = fs::read_dir(path).unwrap();
                for entry in entries {
                    let entry = entry.unwrap();
                    let response = crypter.crypt(entry.path().to_str().unwrap().to_string());
                    if !response.is_empty() {
                        println!("ENCRYPTION KEY: {}", response);
                    }
                }
            } else if file.is_file() {
                let response = crypter.crypt(path.to_owned());
                if !response.is_empty() {
                    println!("ENCRYPTION KEY: {}", response);
                }
            }
        }
    }
}

#[derive(Debug)]
pub enum FilesError {
    NoFiles,
    FileNotFound,
    NoRecursiveFolders,
}

impl fmt::Display for FilesError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match *self {
            FilesError::NoFiles => write!(f, "File list is empty"),
            FilesError::FileNotFound => write!(f, "File not found"),
            FilesError::NoRecursiveFolders => write!(f, "Use -r flag for operations with folders"),
        }
    }
}
