# Arcane

A simple packer for Linux executables and scripts. Arcane compresses and encrypts an executable or `#!` script into a self-extracting binary.

## Features

* **Compression**: Payloads are compressed using [Zstandard](https://facebook.github.io/zstd/) (zstd) for a smaller footprint.
* **Encryption**: Payloads are encrypted using AES-256-GCM with a key derived from a user-provided password using Argon2.
* **In-Memory Execution**: The packed executable, when run, decrypts and decompresses its payload into an in-memory file (`memfd`) and executes it directly. The original executable never touches the disk. Both ELF binaries and `#!` scripts are supported.
* **Self-Contained**: The resulting packed binary is a single, static executable with no external dependencies.

## Usage

To pack an executable:

```
arcane pack [OPTIONS] <INPUT>
```

### Arguments

* `<INPUT>`: Path to the input executable to pack.

### Options

* `-o, --output <PATH>`: Write the packed executable to `<PATH>`. Defaults to `<INPUT>.packed`.
* `-p, --password <PASSWORD>`: Set the password to encrypt the payload. If not provided, you will be prompted for it. This can also be set with the `ARCANE_PASSWORD` environment variable.
* `-h, --help`: Show help output.

## Building

To build Arcane from source, you need the Zig compiler installed.

For a development build:
```
zig build
```

For a faster, optimized release build:
```
zig build -Doptimize=ReleaseFast
```

The executable will be located at `zig-out/bin/arcane`.

## Future Work

* An `unpack` command to get the original executable back.

## License

This project is licensed under the terms of the license in the `COPYING` file.
