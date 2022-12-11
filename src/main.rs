extern crate crypto;
//extern crate filebuffer;
extern crate walkdir;

// naive version
use std::fs;
use std::io;
use std::io::BufRead;
// end naive version
use crypto::digest::Digest;
use crypto::sha2::Sha256;
//use filebuffer::FileBuffer;
use walkdir::WalkDir;

fn main() {
    for entry in WalkDir::new(".").sort_by_file_name().into_iter().filter_map(|e| e.ok()) {
        let fname = entry.path();
        if ! fname.is_file() {
            continue;
        }
        
        let mut sha = Sha256::new();
        // TODO: fixme for more efficient stream handling
//        let fbuffer = FileBuffer::open(&fname).expect("failed to open file");
//        sha.input(&fbuffer);

// naive version
        let file = fs::File::open(&fname).expect("failed to open file");
        let mut reader = io::BufReader::new(file);

        loop {
            let consumed_len = {
                let buffer = reader.fill_buf().expect("failed to read from file");
                if buffer.len() == 0 {
                    // End of file.
                    break;
                }
                sha.input(buffer);
                buffer.len()
            };
            reader.consume(consumed_len);
        }
// end naive version
        
        // TODO: include hash-of-hashes for (sorted) files in directory

        println!("{}: {}", sha.result_str(), fname.display());
    }
}
