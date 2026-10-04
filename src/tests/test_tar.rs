use crate::util::tar::{entry_len, write_header, write_padding, EntryKind, BLOCK_SIZE};

/// Largest size the ustar size field holds; one more needs a PAX record.
const MAX_USTAR_SIZE: u64 = 0o777_7777_7777;

fn header_bytes(path: &str, kind: EntryKind, size: u64, mtime: u64) -> Vec<u8> {
    let mut out = Vec::new();

    write_header(&mut out, path, kind, size, mtime).unwrap();

    out
}

// Header bytes plus the data and padding a writer would add after them.
fn written_len(path: &str, kind: EntryKind, size: u64) -> u64 {
    let data_len = size.div_ceil(BLOCK_SIZE) * BLOCK_SIZE;

    header_bytes(path, kind, size, 0).len() as u64 + data_len
}

#[test]
fn entry_len_matches_written_bytes() {
    let long_path = format!("{}/file", "d".repeat(300));
    let cases = [
        ("dir/", EntryKind::Directory, 0),
        ("dir/file", EntryKind::File, 0),
        ("dir/file", EntryKind::File, 1),
        ("dir/file", EntryKind::File, 512),
        ("dir/file", EntryKind::File, 513),
        (&"a".repeat(100), EntryKind::File, 10),
        (&"a".repeat(101), EntryKind::File, 10),
        (&long_path, EntryKind::File, 70_000),
        ("dir/ünïcode", EntryKind::File, 5),
        ("dir/huge", EntryKind::File, MAX_USTAR_SIZE + 1),
    ];

    for (path, kind, size) in cases {
        assert_eq!(
            entry_len(path, size),
            written_len(path, kind, size),
            "{path:?} {size}"
        );
    }
}

#[test]
fn only_long_or_non_ascii_paths_and_huge_sizes_get_a_pax_header() {
    assert_eq!(entry_len("dir/file", 0), BLOCK_SIZE);
    assert_eq!(entry_len(&"a".repeat(100), 0), BLOCK_SIZE);
    assert_eq!(
        entry_len("dir/file", MAX_USTAR_SIZE),
        BLOCK_SIZE + MAX_USTAR_SIZE + 1
    );

    assert_eq!(entry_len(&"a".repeat(101), 0), 3 * BLOCK_SIZE);
    assert_eq!(entry_len("ü", 0), 3 * BLOCK_SIZE);
    assert_eq!(
        header_bytes("f", EntryKind::File, MAX_USTAR_SIZE + 1, 0)[156],
        b'x'
    );
}

#[test]
fn pax_record_length_counts_its_own_digits() {
    // The shortest paths that get a record, and path lengths around where the
    // record length goes from 3 digits to 4.
    for path_len in (101..110).chain(985..1000) {
        let path = "p".repeat(path_len);
        let out = header_bytes(&path, EntryKind::File, 0, 0);

        let records_len =
            usize::from_str_radix(std::str::from_utf8(&out[124..135]).unwrap(), 8).unwrap();
        let record = std::str::from_utf8(&out[512..512 + records_len]).unwrap();
        let (len, rest) = record.split_once(' ').unwrap();

        assert_eq!(len.parse::<usize>().unwrap(), record.len(), "{path_len}");
        assert_eq!(rest, format!("path={path}\n"));
    }
}

#[test]
fn header_fields_and_checksum() {
    let header = header_bytes("dir/file", EntryKind::File, 0o1234, 0o5670);

    assert_eq!(header.len(), 512);
    assert_eq!(&header[..8], b"dir/file");
    assert_eq!(&header[100..108], b"0000644\0");
    assert_eq!(&header[124..136], b"00000001234\0");
    assert_eq!(&header[136..148], b"00000005670\0");
    assert_eq!(header[156], b'0');
    assert_eq!(&header[257..265], b"ustar\x0000");

    let stored = u32::from_str_radix(std::str::from_utf8(&header[148..154]).unwrap(), 8).unwrap();
    let mut blanked = header.clone();

    blanked[148..156].fill(b' ');

    assert_eq!(stored, blanked.iter().map(|&b| b as u32).sum::<u32>());
    assert_eq!(&header[154..156], b"\0 ");

    let directory = header_bytes("dir/", EntryKind::Directory, 0, 0);

    assert_eq!(&directory[100..108], b"0000755\0");
    assert_eq!(directory[156], b'5');
}

#[test]
fn padding_reaches_the_next_block() {
    for len in [0, 1, 511, 512, 513] {
        let mut out = Vec::new();

        write_padding(&mut out, len).unwrap();

        assert_eq!((len + out.len() as u64) % BLOCK_SIZE, 0);
        assert!(out.len() < BLOCK_SIZE as usize);
    }
}
