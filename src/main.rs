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

#[cfg(feature = "audit")]
use regex::Regex;

use std::collections::HashMap;
use std::io::BufRead;
use std::str::FromStr;
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

/// Representation of a file in the audit map read from previous calls:
#[derive(Debug)]
struct FileEntry {
    path: String,
    present: bool,
    size: usize,
}

impl FileEntry {
    fn new(path: String) -> FileEntry {
        FileEntry { path, present: false, size: 0 }
    }

    fn new_s(path: String, size: usize) -> FileEntry {
        FileEntry { path, present: false, size }
    }
}

fn main() {
    let args = Args::parse();

    // If we have an audit map parameter, then try to parse it - with error handling
    let mut audit_map: Option<HashMap<String, FileEntry>> = None;
    #[cfg(feature = "audit")] {
    if let Some(audit_file) = args.audit {
        println!("Reading hashes from {}", audit_file);
        let faudit = FileBuffer::open(&audit_file).expect(&format!("Failed to open file {}", audit_file).to_string());
        let mut map = HashMap::new();

        for line in faudit.lines().map(|l| l.unwrap_or_default()) {
            let re1 = Regex::new(r"^(?<hash>[[:xdigit:]]+)[[:space:]]+(?<file>.+)[[:space:]]*$");
            let re2 = Regex::new(r"^(?<size>[[:digit:]]+),(?<hash>[[:xdigit:]]+),(?<file>.+)[[:space:]]*$");

            if let Some(caps) = re1.unwrap().captures(line.as_str()) {
                let hash = &caps["hash"];
                let file = &caps["file"];
                println!("Parsing audit file in format 1: {} -> {}", hash, file);
                map.insert(hash.to_string(), FileEntry::new(file.to_string()));
            }
            else if let Some(caps) = re2.unwrap().captures(line.as_str()) {
                let hash = &caps["hash"];
                let file = &caps["file"];
                let size = match usize::from_str(&caps["size"]) {
                    Ok(s) => s,
                    Err(_) => {
                        println!("Cannot parse {} into usize, setting to 0", &caps["size"]);
                        0
                    }
                };
                println!("Parsing audit file in format 2: {} -> {} with size {}", hash, file, size);
                map.insert(hash.to_string(), FileEntry::new_s(hash.to_string(), size));
            }
            else {
                println!("Failed to parse line {}", line);
            }
        }
        //println!("{:#?}", &map);
        audit_map = Some(map);
    }}

    match args.hasher.as_str() {
        #[cfg(feature = "sha2")]
        "sha2" => scan_dir::<sha2::Sha256>(&args.path, &mut audit_map, args.compatoutput),

        #[cfg(feature = "sha3")]
        "sha3" => scan_dir::<sha3::Sha3_256>(&args.path, &mut audit_map, args.compatoutput),

        #[cfg(feature = "blake3")]
        "blake3" => scan_dir::<blake3::Hasher>(&args.path, &mut audit_map, args.compatoutput),

        _ => panic!("unknown hash function")
    };
}

fn scan_dir<D: Digest>(path: &str, audit_map: &mut Option<HashMap<String, FileEntry>>, compat_output: bool)
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
            Some(ref mut m) => {
                #[cfg(feature = "audit")] {
                    let h = format!("{:x}", fhash);
                    if m.contains_key(h.as_str()) {
                        let e = m.get_mut(h.as_str()).unwrap();
                        // remember that we found a file with this hash
                        e.present = true;
                        if e.path != fname.display().to_string() {
                            println!("{:x}  {}  (moved from {})", fhash, fname.display(), e.path);
                        }
                    } else {
                        println!("{:x}  {}  (not found in audit map)", fhash, fname.display());
                    }

                    // TODO: check is the path is present, but (at this point) with a different hash - that's the most important category
                }
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

    #[cfg(feature = "audit")] {
        if let Some(m) = audit_map {
            for (h, e) in m.iter() {
                if !e.present {
                    println!("{}  {}  (not found in filesystem, but listed in audit map)", h, e.path);
                }
            }
        }
    }
}
