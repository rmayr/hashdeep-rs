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

use digest::Digest;
use digest::crypto_common::generic_array::{GenericArray, ArrayLength};
use digest::typenum::U32;
use filebuffer::FileBuffer;
use walkdir::WalkDir;
use clap::Parser;

#[derive(Parser)]
// TODO: why isn't this read from Cargo.toml?
//#[command(author, version, about, long_about = None)]
#[command(author = "René Mayrhofer", version, about = "Recursively compute file hashes over a tree", long_about = None)]
struct Args {
    /// Directory path to start recursive traversal from
    #[arg(short, long, default_value_t = String::from("."))]
    path: String,
 
    /// Hash function: sha2, sha3, or blake3
    #[arg(short = 'c', long, default_value_t = String::from("blake3"))]
    hasher: String,
 }

// Need to implement a local type for implementing the foreign traits
/*pub struct Blake3Wrapper {
    hasher: blake3::Hasher,
}
impl OutputSizeUser for Blake3Wrapper { type OutputSize = u32<32>; }

impl Digest for Blake3Wrapper {
    fn new() -> Self {
        blake3::Hash
        Blake3Wrapper {
            hasher: blake3::Hasher::new()
        }
    }

    fn new_with_prefix(data: impl AsRef<[u8]>) -> Self {
        todo!()
    }

    fn update(&mut self, data: impl AsRef<[u8]>) {
        self.hasher.update(data);
    }

    fn chain_update(self, data: impl AsRef<[u8]>) -> Self {
        let mut h2 = self;
        h2.update(data);
        h2
    }

    fn finalize(self) -> Output<Self> {
        self.hasher.finalize().into()
    }

    fn finalize_into(self, out: &mut Output<Self>) {
        todo!()
    }

    fn finalize_reset(&mut self) -> Output<Self> where Self: FixedOutputReset {
        todo!()
    }

    fn finalize_into_reset(&mut self, out: &mut Output<Self>) where Self: FixedOutputReset {
        todo!()
    }

    fn reset(&mut self) where Self: Reset {
        self.hasher.reset();
    }

    fn output_size() -> usize {
        todo!()
    }

    fn digest(data: impl AsRef<[u8]>) -> Output<Self> {
        todo!()
    }
}*/

fn main() {
    let args = Args::parse();

    let mut digest: Box<dyn Digest<OutputSize=GenericArray<u8, U32>>> = match args.hasher.as_str() {
        #[cfg(feature = "sha2")]
        "sha2" => Box::new(sha2::Sha256::new()),

        #[cfg(feature = "sha3")]
        "sha3" => Box::new(sha3::Sha3_256::new()),

        #[cfg(feature = "blake3")]
        "blake3" => Box::new(blake3::Hasher::new()),

        _ => panic!("unknown hash function")
    };

    for entry in WalkDir::new(args.path).sort_by_file_name().into_iter().filter_map(|e| e.ok()) {
        let fname = entry.path();
        if ! fname.is_file() {
            continue;
        }
        
        let fbuf = FileBuffer::open(&fname).expect(&format!("failed to open file {}", fname.display()).to_string());
        digest.reset();
        digest.update(&fbuf);

        let fhash = digest.finalize();
        // TODO: include hash-of-hashes for (sorted) files in directory

        println!("{}: {}", fhash.to_hex(), fname.display());
    }
}
