use memchr::memmem::Finder;

pub fn query(text: &str, hex: bool) -> Result<Vec<u8>, &'static str> {
    if hex {
        let mut digits = String::new();
        for c in text.chars() {
            if c.is_ascii_hexdigit() { digits.push(c); }
            else if !c.is_ascii_whitespace() && c != ':' && c != '-' { return Err("Use hexadecimal digits, spaces, colons, or hyphens"); }
        }
        if digits.is_empty() || digits.len() & 1 != 0 { return Err("Enter an even number of hexadecimal digits"); }
        if digits.len() > 8192 { return Err("Search pattern exceeds 4096 bytes"); }
        Ok(digits.as_bytes().chunks_exact(2).map(|p| u8::from_str_radix(std::str::from_utf8(p).unwrap(), 16).unwrap()).collect())
    } else {
        if text.is_empty() { return Err("Enter a text search pattern"); }
        if text.len() > 4096 { return Err("Search pattern exceeds 4096 bytes"); }
        Ok(text.as_bytes().to_vec())
    }
}
pub fn find(data: &[u8], pattern: &[u8], limit: usize) -> Vec<usize> {
    if pattern.is_empty() || limit == 0 { return Vec::new(); }
    let finder = Finder::new(pattern);
    let mut matches = Vec::new(); let mut start = 0;
    while start <= data.len() {
        match finder.find(&data[start..]) {
            Some(offset) => { let index = start + offset; matches.push(index); if matches.len() >= limit { break; } start = index + 1; }
            None => break,
        }
    }
    matches
}
pub fn find_sparse(data: &[Option<u8>], pattern: &[u8], limit: usize) -> Vec<usize> {
    let mut matches = Vec::new(); let mut start = 0;
    while start < data.len() && matches.len() < limit {
        while start < data.len() && data[start].is_none() { start += 1; }
        let mut end = start;
        while end < data.len() && data[end].is_some() { end += 1; }
        if end > start {
            let bytes: Vec<u8> = data[start..end].iter().map(|x| x.unwrap()).collect();
            matches.extend(find(&bytes, pattern, limit - matches.len()).into_iter().map(|i| i + start));
        }
        start = end.saturating_add(1);
    }
    matches
}
#[cfg(test)] mod tests {
    use super::*;
    #[test] fn overlapping_matches_and_hex_validation() {
        assert_eq!(find(b"aaaa", b"aa", 10), vec![0,1,2]);
        assert_eq!(query("41 42:ff", true).unwrap(), vec![65,66,255]);
        assert!(query("ABC", true).is_err());
    }
    #[test] fn sparse_search_never_crosses_gaps() {
        let d = [Some(b'A'), None, Some(b'B'), Some(b'A'), Some(b'B')];
        assert_eq!(find_sparse(&d, b"AB", 10), vec![3]);
    }
    #[test] fn utf8_and_result_limit_are_byte_accurate() {
        let q = query("你好",false).unwrap();
        assert_eq!(find("x你好你好".as_bytes(), &q, 1), vec![1]);
        assert!(query("",false).is_err());
        assert!(query("GG",true).is_err());
    }
}
