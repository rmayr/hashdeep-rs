NOTE: MOVED TO [https://codeberg.org/rmayr/dvcs-autosync](https://codeberg.org/rmayr/hashdeep-rs) because Github is now a subsidiary of Microsoft AI stuff.
===

# hashdeep-rs

This is a very simple implementation of hashdeep in Rust. It computes hashes of all files recursively starting from the current directory. The hash function can currently be SHA2, SHA3, or Blake3, all with 256 Bit output. It is not at this time intended to be a generic tool, but mostly for comparing two file trees using locally computed hashes. My primary use case is to compute the list of (sorted) hashes of a large/deep directory tree on different hosts using this tool, transfer one of the output lists to the other, and then diff the outputs. That is, I currently use it for verifying backups or remote synchronization, but don't use it as a forensic tool yet.

Pull requests for additional options are welcome, although I don't intend to spend a lot of time on maintenance. This was more an exercise in quickly creating a tool for a specific need and slightly improving my Rust knowledge in the process.
