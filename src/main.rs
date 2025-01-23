extern crate digest;
extern crate walkdir;
extern crate filebuffer;
extern crate clap;

#[cfg(feature = "sha2")]
extern crate sha2;

#[cfg(feature = "sha3")]
extern crate sha3;

#[cfg(feature = "blake3")]
extern crate blake3;

use std::collections::HashMap;
use std::io::BufRead;
use digest::Digest;
use filebuffer::FileBuffer;
use walkdir::WalkDir;
use clap::Parser;

#[derive(Parser)]
#[command(author, version, about, long_about = "Recursively compute or verify (in audit mode) hashes over a directory tree, sorted lexicographically for deterministic output and supporting different hash algorithms. This is a lot like the older sha*deep utilities, but uses memory safe code and parallelizes I/O access for fast operation.")]
struct Args {
    /// Directory path to start recursive traversal from
    #[arg(short = 'p', long, default_value_t = String::from("."))]
    path: String,
 
    /// Hash function: sha2, sha3, or blake3
    #[arg(short = 'c', long, default_value_t = String::from("blake3"))]
    hasher: String,

    /// Auditing mode: read hashes from file specific by this parameter and compare with files in path.
    #[arg(short = 'a', long)]
    audit: Option<String>,

    /// Compatibility flag for easier replacement of hashdeep/sha256deep/sha3deep: ignored because hashdeep-rs works in recursive mode by default
    #[arg(short = 'r', long)]
    recursive: bool,

    /// Compatibility flag for easier replacement of hashdeep: output uses the <size>,<hash>,<full absolute file path> format
    #[arg(short = 'C', long, default_value_t = false)]
    compatoutput: bool,
}

fn main() {
    let args = Args::parse();

    let mut audit_map: Option<HashMap<String, String>> = None;
    if let Some(audit_file) = args.audit {
        println!("Reading hashes from {}", audit_file);
        let faudit = FileBuffer::open(&audit_file).expect(&format!("Failed to open file {}", audit_file).to_string());
        let map: HashMap<String, String> = faudit.lines().map(|l| l.unwrap_or_default()
                .split_once(char::is_whitespace).expect("Unable to split line {}, audit file is in invalid format")
                .map(| (l, r) | (l.to_string(), r.to_string()))).collect();
        println!("{:#?}", &map);
        audit_map = Some(map);
    }

    match args.hasher.as_str() {
        #[cfg(feature = "sha2")]
        "sha2" => scan_dir::<sha2::Sha256>(&args.path, audit_map, args.compatoutput),

        #[cfg(feature = "sha3")]
        "sha3" => scan_dir::<sha3::Sha3_256>(&args.path, audit_map, args.compatoutput),

        #[cfg(feature = "blake3")]
        "blake3" => scan_dir::<blake3::Hasher>(&args.path, audit_map, args.compatoutput),

        _ => panic!("unknown hash function")
    };
}

fn scan_dir<D: Digest>(path: &str, audit_map: Option<HashMap<String, String>>, compat_output: bool)
        where D::OutputSize: std::ops::Add,
              <D::OutputSize as std::ops::Add>::Output: digest::generic_array::ArrayLength<u8> {

    // TODO: parallelize for efficiency, but keep ordering for output, see e.g. https://users.rust-lang.org/t/whats-the-fastest-way-to-read-a-lot-of-files/39743/10
    for entry in WalkDir::new(path).sort_by_file_name().into_iter().filter_map(|e| e.ok()) {
        let fname = entry.path();
        if ! fname.is_file() {
            continue;
        }

        let fbuf = FileBuffer::open(&fname).expect(&format!("Failed to open file {}", fname.display()).to_string());

        // this may not be optimal from a performance point of view, but reset is problematic with re-using the digest in the generic case
        let mut digest = D::new();
        //Digest::reset(&mut digest);
        digest.update(&fbuf);

        let fhash = digest.finalize();
        match audit_map {
            Some(ref _m) => {
                /*if m.contains_key(&fhash.to_string()) {
                    if (m.get(&fhash.to_string()).unwrap() != fname.display().to_string()) {
                        println!("{}  {}  (mismatch)", fhash, fname.display());
                    }
                }*/
            },
            None => {
                if compat_output {
                    println!("{},{:x},{}", fname.metadata().expect("Failed to get file metadata of {}").len(), fhash,
                             fname.canonicalize().expect("Failed to canonicalize path {}").display());
                } else {
                    println!("{:x}  {}", fhash, fname.display());
                }
            }
        }
    }
}
