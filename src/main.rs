extern crate crypto;
extern crate walkdir;
extern crate filebuffer;

use crypto::digest::Digest;
use crypto::sha2::Sha256;
use filebuffer::FileBuffer;
use walkdir::WalkDir;

fn main() {
    for entry in WalkDir::new(".").sort_by_file_name().into_iter().filter_map(|e| e.ok()) {
        let fname = entry.path();
        if ! fname.is_file() {
            continue;
        }
        
        let mut hasher = Sha256::new();
        let fbuf = FileBuffer::open(&fname).expect(&format!("failed to open file {}", fname.display()).to_string());
        hasher.input(&fbuf);

        // TODO: include hash-of-hashes for (sorted) files in directory

        println!("{}: {}", hasher.result_str(), fname.display());
    }
}
