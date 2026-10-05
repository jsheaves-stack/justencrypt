//! Writes uncompressed TAR archives: ustar headers, with a PAX extended header
//! in front of any entry whose path or size doesn't fit the ustar fields.
//! [`entry_len`] gives the exact number of bytes [`write_header`] and
//! [`write_padding`] produce for an entry, so an archive's length can be
//! known before any of it is written.

use std::io::{self, Write};

/// Everything in a TAR archive comes in blocks of this many bytes.
pub const BLOCK_SIZE: u64 = 512;

/// Length of the end-of-archive marker: two zero blocks.
pub const END_LEN: u64 = 2 * BLOCK_SIZE;

const NAME_LEN: usize = 100;

/// Largest size the 12-byte ustar size field can hold: 11 octal digits.
const MAX_USTAR_SIZE: u64 = 0o777_7777_7777;

const ZERO_BLOCK: [u8; BLOCK_SIZE as usize] = [0; BLOCK_SIZE as usize];

/// What an archive entry is.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum EntryKind {
    File,
    Directory,
}

/// Bytes an entry takes in the archive: its headers, its data and the
/// padding after the data. A directory's `path` ends with `/` and its
/// `size` is 0.
pub fn entry_len(path: &str, size: u64) -> u64 {
    let pax_len = match pax_records(path, size) {
        Some(records) => BLOCK_SIZE + padded_len(records.len() as u64),
        None => 0,
    };

    pax_len + BLOCK_SIZE + padded_len(size)
}

/// Writes the headers of an entry. A file's `size` bytes of data and then
/// [`write_padding`] must follow.
pub fn write_header(
    w: &mut impl Write,
    path: &str,
    kind: EntryKind,
    size: u64,
    mtime: u64,
) -> io::Result<()> {
    if let Some(records) = pax_records(path, size) {
        let records = records.as_bytes();

        w.write_all(&ustar_header(
            b"././@PaxHeader",
            b'x',
            records.len() as u64,
            mtime,
            0o644,
        ))?;
        w.write_all(records)?;
        write_padding(w, records.len() as u64)?;
    }

    let (type_flag, mode) = match kind {
        EntryKind::File => (b'0', 0o644),
        EntryKind::Directory => (b'5', 0o755),
    };

    // Readers take the path and size from the PAX header when there is one,
    // so the ustar fields only need to hold something.
    let name = &path.as_bytes()[..path.len().min(NAME_LEN)];
    let ustar_size = if size > MAX_USTAR_SIZE { 0 } else { size };

    w.write_all(&ustar_header(name, type_flag, ustar_size, mtime, mode))
}

/// Pads `len` bytes of data out to the next block boundary.
pub fn write_padding(w: &mut impl Write, len: u64) -> io::Result<()> {
    let padding = (padded_len(len) - len) as usize;

    w.write_all(&ZERO_BLOCK[..padding])
}

/// Writes the end-of-archive marker: two zero blocks.
pub fn write_end(w: &mut impl Write) -> io::Result<()> {
    w.write_all(&ZERO_BLOCK)?;
    w.write_all(&ZERO_BLOCK)
}

/// `len` rounded up to a whole number of blocks.
fn padded_len(len: u64) -> u64 {
    len.div_ceil(BLOCK_SIZE) * BLOCK_SIZE
}

/// The PAX records an entry needs, if any. A path goes in a record when it
/// doesn't fit the ustar name field or isn't ASCII (ustar fields have no
/// defined encoding; PAX paths are UTF-8).
fn pax_records(path: &str, size: u64) -> Option<String> {
    let mut records = String::new();

    if path.len() > NAME_LEN || !path.is_ascii() {
        records.push_str(&pax_record("path", path));
    }

    if size > MAX_USTAR_SIZE {
        records.push_str(&pax_record("size", &size.to_string()));
    }

    (!records.is_empty()).then_some(records)
}

/// A record is `"<len> <key>=<value>\n"`, where `len` counts the whole
/// record, its own digits included.
fn pax_record(key: &str, value: &str) -> String {
    let rest = key.len() + value.len() + 3;
    let mut len = rest + 1;

    while len != rest + decimal_digits(len) {
        len = rest + decimal_digits(len);
    }

    format!("{len} {key}={value}\n")
}

/// How many digits `n` has in decimal.
fn decimal_digits(n: usize) -> usize {
    n.to_string().len()
}

/// A ustar header block for an entry named `name` (at most 100 bytes), with
/// its checksum filled in.
fn ustar_header(name: &[u8], type_flag: u8, size: u64, mtime: u64, mode: u32) -> [u8; 512] {
    let mut header = [0u8; 512];

    header[..name.len()].copy_from_slice(name);
    write_octal(&mut header[100..108], mode as u64);
    write_octal(&mut header[108..116], 0);
    write_octal(&mut header[116..124], 0);
    write_octal(&mut header[124..136], size);
    write_octal(&mut header[136..148], mtime.min(MAX_USTAR_SIZE));
    header[156] = type_flag;
    header[257..263].copy_from_slice(b"ustar\0");
    header[263..265].copy_from_slice(b"00");

    // The checksum is computed with its own field set to spaces.
    header[148..156].fill(b' ');

    let checksum: u32 = header.iter().map(|&b| b as u32).sum();

    header[148..156].copy_from_slice(format!("{checksum:06o}\0 ").as_bytes());

    header
}

/// Zero-padded octal digits filling all but the last byte of `field`, then a
/// NUL.
fn write_octal(field: &mut [u8], value: u64) {
    let digits = field.len() - 1;

    field[..digits].copy_from_slice(format!("{value:0digits$o}").as_bytes());
    field[digits] = 0;
}
