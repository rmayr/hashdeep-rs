//extern crate crypto;
extern crate blake3;
extern crate walkdir;
extern crate filebuffer;
extern crate clap;

/*use crypto::digest::Digest;
use crypto::sha2::Sha256;*/
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
 
    /// Hash function: sha256 or blake3
    #[arg(short = 'c', long, default_value_t = String::from("blake3"))]
    hasher: String,
 }

fn main() {
    let args = Args::parse();

    let mut hasher = /*match args.hasher {
        "sha256" => Sha256::new() ,
        "blake3" => */ blake3::Hasher::new() /*,
        _ => panic!("unknown hash function")
    }*/;

    for entry in WalkDir::new(args.path).sort_by_file_name().into_iter().filter_map(|e| e.ok()) {
        let fname = entry.path();
        if ! fname.is_file() {
            continue;
        }
        
        let fbuf = FileBuffer::open(&fname).expect(&format!("failed to open file {}", fname.display()).to_string());
        /*let mut hasher = match args.hasher  {
            "sha256" => Sha256::new(),
            "blake3" => blake3::Hasher::new(),
            _ => panic!("unknown hash function"),
        } */ ;
        hasher.reset();
        hasher.update(&fbuf);

        // TODO: include hash-of-hashes for (sorted) files in directory

        println!("{}: {}", hasher.finalize().to_hex(), fname.display());
    }
}
