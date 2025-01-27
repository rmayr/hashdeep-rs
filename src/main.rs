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
use std::rc::Rc;
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
    hash: String,
    path: String,
    present: bool,
    size: usize,
}

impl FileEntry {
    fn new(hash: String, path: String) -> Rc<FileEntry> {
        Rc::new(FileEntry { hash, path, present: false, size: 0 })
    }

    fn new_s(hash: String, path: String, size: usize) -> Rc<FileEntry> {
        Rc::new(FileEntry { hash, path, present: false, size })
    }
}

/// Encapsulates FileEntry structs that were read from the audit file, indexed
/// both by hash and by path.
#[derive(Debug)]
struct AuditMap<'a> {
    by_hash: HashMap<&'a str, usize>,
    by_path: HashMap<&'a str, usize>,
    data: Vec<Rc<FileEntry>>,
}

impl<'a> AuditMap<'a> {
    fn new() -> AuditMap<'a> {
        let by_hash = HashMap::new();
        let by_path = HashMap::new();
        let data = Vec::new();
        AuditMap { by_hash, by_path, data }
    }

    fn insert(&mut self, entry: Rc<FileEntry>) {
        let hash = Rc::clone(&entry).hash.as_str();
        let path = Rc::clone(&entry).path.as_str();

        self.data.push(entry);
        self.by_hash.insert(hash, self.data.len());
        self.by_path.insert(path, self.data.len());
    }

    fn get_by_hash(&mut self, hash: &str) -> Option<&mut Rc<FileEntry>> {
        if let Some(i) = self.by_hash.get(hash) {
            self.data.get_mut(*i)
        }
        else {
            None
        }
    }

    fn get_by_path(&mut self, path: &str) -> Option<&mut Rc<FileEntry>> {
        if let Some(i) = self.by_path.get(path) {
            self.data.get_mut(*i)
        }
        else {
            None
        }
    }

    fn iter(&self) -> impl Iterator<Item=&Rc<FileEntry>> {
        self.data.iter()
    }
}

fn main() {
    let args = Args::parse();

    /* If we have an audit map parameter, then try to parse it - with error handling.
       For efficiency during the later file system traversal, construct two maps: one
       indexed by path, ony by hash.
       This uses Rcs because we want to have the same FileEntry sructs referenced
       from both index maps and be able to, e.g., update the present bool only once in
       addition to efficient deduplicated memory handling. */
    let mut audit_map: Option<AuditMap> = None;
    #[cfg(feature = "audit")] {
    if let Some(audit_file) = args.audit {
        println!("Reading hashes from {}", audit_file);
        let faudit = FileBuffer::open(&audit_file).expect(&format!("Failed to open file {}", audit_file).to_string());
        let mut map = AuditMap::new();

        for line in faudit.lines().map(|l| l.unwrap_or_default()) {
            let re1 = Regex::new(r"^(?<hash>[[:xdigit:]]+)[[:space:]]+(?<file>.+)[[:space:]]*$");
            let re2 = Regex::new(r"^(?<size>[[:digit:]]+),(?<hash>[[:xdigit:]]+),(?<file>.+)[[:space:]]*$");
            let mut entry = None;

            if let Some(caps) = re1.unwrap().captures(line.as_str()) {
                let hash = &caps["hash"];
                let file = &caps["file"];
                println!("Parsing audit file in format 1: {} -> {}", hash, file);
                entry = Some(FileEntry::new(hash.to_string(), file.to_string()));
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
                entry = Some(FileEntry::new_s(hash.to_string(), file.to_string(), size));
            }
            else {
                println!("Failed to parse line {}", line);
            }

            if let Some(e) = entry {
                map.insert(e);
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

fn scan_dir<D: Digest>(path: &str, audit_map: &mut Option<AuditMap>, compat_output: bool)
        where D::OutputSize: std::ops::Add,
              <D::OutputSize as std::ops::Add>::Output: digest::generic_array::ArrayLength<u8> {

    // TODO: parallelize for efficiency, but keep ordering for output, see e.g. https://users.rust-lang.org/t/whats-the-fastest-way-to-read-a-lot-of-files/39743/10
    for entry in WalkDir::new(path).sort_by_file_name().into_iter().filter_map(|e| e.ok()) {
        let file = entry.path();
        if ! file.is_file() {
            continue;
        }

        let fbuf = FileBuffer::open(&file).expect(&format!("Failed to open file {}", file.display()).to_string());

        // this may not be optimal from a performance point of view, but reset is problematic with re-using the digest in the generic case
        let mut digest = D::new();
        //Digest::reset(&mut digest);
        digest.update(&fbuf);

        let fhash = digest.finalize();
        let h = format!("{:x}", fhash);
        let n = file.display().to_string();
        match audit_map {
            Some(ref mut m) => {
                #[cfg(feature = "audit")] {
                    if let Some(e) = m.get_by_hash(h.as_str()) {
                        // remember that we found a file with this hash
                        e.present = true;
                        if e.path == n {
                            println!("{} -> {}  (OK)", h, n);
                        }
                        else {
                            println!("{}  {}  (MOVED from {})", h, n, e.path);
                        }
                    } else if let Some(e) = m.get_by_path(n.as_str()) {
                        e.present = true;
                        if e.hash != h {
                            println!("{}  {}  (CHANGED hash from {})", h, n, e.hash);
                        }
                        else {
                            panic!("Found a duplicate hash/path combination after checking for that case - this shouldn't happen");
                        }
                    } else {
                        println!("{}  {}  (NEW, not found in audit map)", h, n);
                    }
                }
            },
            None => {
                if compat_output {
                    println!("{},{},{}", file.metadata().expect("Failed to get file metadata of {}").len(), h,
                             file.canonicalize().expect("Failed to canonicalize path {}").display());
                } else {
                    println!("{}  {}", h, n);
                }
            }
        }
    }

    #[cfg(feature = "audit")] {
        if let Some(m) = audit_map {
            for e in m.iter().filter(|e| !e.present) {
                println!("{}  {}  (MISSING in filesystem, but listed in audit map)", e.hash, e.path);
            }
        }
    }
}
