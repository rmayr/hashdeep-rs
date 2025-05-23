#[cfg(feature = "sha2")]
extern crate sha2;

#[cfg(feature = "sha3")]
extern crate sha3;

#[cfg(feature = "blake3")]
extern crate blake3;

#[cfg(feature = "audit")]
use colored::Colorize;
#[cfg(feature = "audit")]
use std::io::BufRead;
#[cfg(feature = "audit")]
use std::collections::HashMap;
#[cfg(feature = "audit")]
use std::str::FromStr;

#[cfg(feature = "parallel")]
use jwalk::WalkDir;
#[cfg(not(feature = "parallel"))]
use walkdir::WalkDir;

use digest::Digest;
use filebuffer::FileBuffer;
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

#[cfg(feature = "audit")]
/// Representation of a file in the audit map read from previous calls:
#[derive(Debug)]
struct FileEntry {
    hash: String,
    path: String,
    present: bool,
    size: u64,
}

#[cfg(feature = "audit")]
impl FileEntry {
    fn new(hash: String, path: String) -> FileEntry {
        FileEntry { hash, path, present: false, size: 0 }
    }

    fn new_s(hash: String, path: String, size: u64) -> FileEntry {
        FileEntry { hash, path, present: false, size }
    }
}

#[cfg(feature = "audit")]
/// Encapsulates FileEntry structs that were read from the audit file, indexed
/// both by hash and by path.
#[derive(Debug)]
struct AuditMap {
    by_hash: HashMap<String, usize>,
    by_path: HashMap<String, usize>,
    data: Vec<FileEntry>,
}
#[cfg(not(feature = "audit"))]
struct AuditMap {}

#[cfg(feature = "audit")]
impl AuditMap {
    fn new() -> AuditMap {
        let by_hash = HashMap::new();
        let by_path = HashMap::new();
        let data = Vec::new();
        AuditMap { by_hash, by_path, data }
    }

    fn insert(&mut self, entry: FileEntry) {
        // TODO: could these strings be &str referencing to the entry stored in the Vec to save some memory?
        let hash = entry.hash.clone();
        let path = entry.path.clone();

        self.data.push(entry);
        self.by_hash.insert(hash, self.data.len()-1);
        self.by_path.insert(path, self.data.len()-1);
    }

    fn get_by_hash(&mut self, hash: &str) -> Option<&mut FileEntry> {
        if let Some(i) = self.by_hash.get(hash) {
            self.data.get_mut(*i)
        }
        else {
            None
        }
    }

    fn get_by_path(&mut self, path: &str) -> Option<&mut FileEntry> {
        if let Some(i) = self.by_path.get(path) {
            self.data.get_mut(*i)
        }
        else {
            None
        }
    }

    fn iter(&self) -> impl Iterator<Item=&FileEntry> {
        self.data.iter()
    }
}

fn main() {
    let args = Args::parse();

    let mut audit_map: Option<AuditMap> = None;
    #[cfg(feature = "audit")] {
    if let Some(audit_file) = args.audit {
        println!("Reading hashes from {}", audit_file);
        let faudit = FileBuffer::open(&audit_file).expect(&format!("Failed to open file {}", audit_file).to_string());
        let mut map = AuditMap::new();

        for line in faudit.lines().map(|l| l.unwrap_or_default()) {
            let mut entry = None;

            if let Some((hash, file)) = line.split_once(char::is_whitespace) {
                //println!("Parsing audit file in format 1: {} -> {}", hash.trim(), file.trim());
                entry = Some(FileEntry::new(hash.trim().to_string(), file.trim().to_string()));
            }
            else {
                let p: Vec<&str> = line.split(',').collect();
                if p.len() == 3 {
                    let size = match u64::from_str(p[0]) {
                        Ok(s) => s,
                        Err(_) => {
                            println!("Cannot parse {} into usize, setting to 0", p[0]);
                            0
                        }
                    };
                    let hash = p[1].trim();
                    let file = p[2].trim();
                    //println!("Parsing audit file in format 2: {} -> {} with size {}", hash, file, size);
                    entry = Some(FileEntry::new_s(hash.to_string(), file.to_string(), size));
                }
                else {
                    println!("Failed to parse line {}", line);
                }
            }

            if let Some(e) = entry {
                // TODO: Decide if this is the right thing to do to ignore duplicate hashes - probably not, should index on hash+path instead
                if let Some(e2) = map.get_by_hash(e.hash.as_str()) {
                    println!("{}  {}  ({} hash with {})", e.hash, e.path, "DUPLICATE".blue(), e2.path);
                }
                else {
                    map.insert(e);
                }
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

// Helper struct to store file information for sorting
#[cfg(feature = "parallel")]
struct FileInfo {
    path: String,
    hash: String,
    size: Option<u64>, // Conditionally populated
    canonical_path: Option<String>, // Conditionally populated for compat_output
}

// Helper function to process a file entry (audit/print)
fn process_file_entry(
    file_path_str: &str,
    hash_str: &str,
    current_file_size_opt: Option<u64>,
    canonical_file_path_opt: Option<&str>, // Changed to Option<&str>
    audit_map: &mut Option<AuditMap>,
    compat_output: bool,
) {
    match audit_map {
        Some(ref mut m) => {
            #[cfg(feature = "audit")] {
                let current_file_size = current_file_size_opt.expect("Size should be present for audit");
                if let Some(e) = m.get_by_hash(hash_str) {
                    e.present = true;
                    if e.path == file_path_str {
                        if e.size == 0 || e.size == current_file_size {
                            println!("{} -> {}  ({})", hash_str, file_path_str, "OK".green());
                        } else {
                            println!("{} -> {}  ({} from {} to {})", hash_str, file_path_str, "CHANGED SIZE".red(), e.size, current_file_size);
                        }
                    } else {
                        println!("{}  {}  ({} from {})", hash_str, file_path_str, "MOVED".blue(), e.path);
                    }
                } else if let Some(e) = m.get_by_path(file_path_str) {
                    e.present = true;
                    if e.hash != hash_str {
                        println!("{}  {}  ({} hash from {})", hash_str, file_path_str, "CHANGED".red(), e.hash);
                    } else {
                        panic!("Found a duplicate hash/path combination after checking for that case - this shouldn't happen");
                    }
                } else {
                    println!("{}  {}  ({} in filesystem with size {})", hash_str, file_path_str, "NEW".yellow(), current_file_size);
                }
            }
            #[cfg(not(feature = "audit"))] {
                // This case should ideally not be hit if audit_map is Some but audit feature is off.
                // However, to be safe and print something:
                if compat_output {
                     println!("{},{},{}", current_file_size_opt.expect("Size for compat"), hash_str, canonical_file_path_opt.expect("Canon path for compat"));
                } else {
                    println!("{}  {}", hash_str, file_path_str);
                }
            }
        },
        None => {
            if compat_output {
                println!("{},{},{}", current_file_size_opt.expect("Size should be present for compat_output"), hash_str, canonical_file_path_opt.expect("Canonical path should be present for compat_output"));
            } else {
                println!("{}  {}", hash_str, file_path_str);
            }
        }
    }
}


fn scan_dir<D: Digest>(path: &str, audit_map: &mut Option<AuditMap>, compat_output: bool)
        where D::OutputSize: std::ops::Add,
              <D::OutputSize as std::ops::Add>::Output: digest::generic_array::ArrayLength<u8> {

    #[cfg(feature = "parallel")]
    {
        let dir_iter = WalkDir::new(path).sort(true).into_iter();
        let mut file_infos: Vec<FileInfo> = Vec::new();

        for entry in dir_iter.filter_map(|e| e.ok()) {
            let file_path = entry.path();
            if !file_path.is_file() {
                continue;
            }

            let fbuf = FileBuffer::open(&file_path).expect(&format!("Failed to open file {}", file_path.display()).to_string());
            let mut digest = D::new();
            digest.update(&fbuf);
            let fhash = digest.finalize();
            let h = format!("{:x}", fhash);
            let n = file_path.display().to_string();

            let mut file_size: Option<u64> = None;
            if compat_output || audit_map.is_some() {
                file_size = Some(file_path.metadata().expect("Failed to get file metadata for size").len());
            }

            let mut canon_path_str_opt: Option<String> = None;
            if compat_output {
                canon_path_str_opt = Some(file_path.canonicalize().expect("Failed to canonicalize path").display().to_string());
            }
            
            file_infos.push(FileInfo { path: n, hash: h, size: file_size, canonical_path: canon_path_str_opt });
        }

        file_infos.sort_by(|a, b| a.path.cmp(&b.path));

        for info in file_infos {
            process_file_entry(
                &info.path,
                &info.hash,
                info.size,
                info.canonical_path.as_deref(),
                audit_map,
                compat_output,
            );
        }
    }

    #[cfg(not(feature = "parallel"))]
    {
        let dir_iter = walkdir::WalkDir::new(path).sort_by_file_name().into_iter();
        for entry in dir_iter.filter_map(|e| e.ok()) {
            let file = entry.path();
            if ! file.is_file() {
                continue;
            }

            let fbuf = FileBuffer::open(&file).expect(&format!("Failed to open file {}", file.display()).to_string());
            let mut digest = D::new();
            digest.update(&fbuf);
            let fhash = digest.finalize();
            let h = format!("{:x}", fhash);
            let n = file.display().to_string();

            let mut current_file_size_opt: Option<u64> = None;
            if compat_output || audit_map.is_some() {
                current_file_size_opt = Some(file.metadata().expect("Failed to get file metadata for size").len());
            }

            let canonical_path_holder: Option<String>; // To hold the String if canonicalized
            let mut canonical_path_display_opt: Option<&str> = None;
            if compat_output {
                let canon_path = file.canonicalize().expect("Failed to canonicalize path {}").display().to_string();
                canonical_path_holder = Some(canon_path);
                canonical_path_display_opt = canonical_path_holder.as_deref();
            } else {
                // canonical_path_holder is not assigned here, but rust requires it to be initialized
                // if it's used later. However, it's only dereferenced if compat_output is true.
                // To satisfy the compiler for all paths if it were used unconditionally:
                canonical_path_holder = None; 
            }
            
            process_file_entry(
                &n,
                &h,
                current_file_size_opt,
                canonical_path_display_opt,
                audit_map,
                compat_output,
            );
        }
    }

    #[cfg(feature = "audit")] {
        if let Some(m) = audit_map {
            for e in m.iter().filter(|e| !e.present) {
                if e.size != 0 {
                    println!("{}  {}  ({} in filesystem with expected size {})", e.hash, e.path, "MISSING".magenta(), e.size);
                }
                else {
                    println!("{}  {}  ({} in filesystem)", e.hash, e.path, "MISSING".magenta());
                }
            }
        }
    }
}
