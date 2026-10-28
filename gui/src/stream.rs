use std::collections::BTreeMap;
use std::net::Ipv4Addr;

type Endpoint = (Ipv4Addr, u16);
struct Segment { seq: u32, bytes: Vec<u8> }
pub struct Direction {
    pub label: String,
    pub base_seq: u32,
    pub data: Vec<Option<u8>>,
    pub missing: usize,
    pub retransmitted: usize,
    pub conflicts: usize,
}
pub struct Stream { pub directions: Vec<Direction>, pub packets: usize, pub skipped_fragments: usize, pub truncated_packets: usize }
fn u16be(b: &[u8], p: usize) -> Option<u16> { Some(u16::from_be_bytes([*b.get(p)?, *b.get(p+1)?])) }
fn parse(p: &[u8]) -> Option<(Endpoint, Endpoint, u32, &[u8])> {
    if p.len() < 20 || p[0] >> 4 != 4 || p[9] != 6 || u16be(p,6)? & 0x3fff != 0 { return None; }
    let h = (p[0] as usize & 15) * 4;
    if h < 20 || p.len() < h + 20 { return None; }
    let tcp = (p[h + 12] as usize >> 4) * 4;
    if tcp < 20 || h + tcp > p.len() { return None; }
    let total = u16be(p,2)? as usize;
    if total < h + tcp { return None; }
    let end = total.min(p.len());
    let src = (Ipv4Addr::new(p[12],p[13],p[14],p[15]), u16be(p,h)?);
    let dst = (Ipv4Addr::new(p[16],p[17],p[18],p[19]), u16be(p,h+2)?);
    let seq = u32::from_be_bytes([p[h+4],p[h+5],p[h+6],p[h+7]]).wrapping_add(if p[h+13] & 0x02 != 0 { 1 } else { 0 });
    Some((src,dst,seq,&p[h+tcp..end]))
}
pub fn build(packets: &[Vec<u8>]) -> Result<Stream, String> {
    let mut groups: BTreeMap<(Endpoint,Endpoint),Vec<Segment>> = BTreeMap::new();
    let mut skipped_fragments = 0;
    let mut truncated_packets = 0;
    for p in packets {
        if p.len() >= 20 && p[0] >> 4 == 4 && p[9] == 6 && u16be(p,6).unwrap_or(0) & 0x3fff != 0 { skipped_fragments += 1; continue; }
        if p.len() >= 20 && p[0] >> 4 == 4 && p[9] == 6 && u16be(p,2).is_some_and(|n| n as usize > p.len()) { truncated_packets += 1; }
        if let Some((src,dst,seq,payload)) = parse(p) {
            if !payload.is_empty() { groups.entry((src,dst)).or_default().push(Segment { seq, bytes: payload.to_vec() }); }
        }
    }
    let mut directions = Vec::new();
    for ((src,dst),segments) in groups {
        let anchor = segments[0].seq;
        let offsets: Vec<i64> = segments.iter().map(|s| s.seq.wrapping_sub(anchor) as i32 as i64).collect();
        let min = *offsets.iter().min().unwrap();
        let max = segments.iter().zip(&offsets).map(|(s,n)| *n + s.bytes.len() as i64).max().unwrap();
        let span = (max-min) as usize;
        if span > 8 * 1024 * 1024 { return Err("TCP sequence span exceeds 8 MiB; narrow the retained packet set".into()); }
        let mut data = vec![None; span]; let mut retransmitted = 0; let mut conflicts = 0;
        for (seg, offset) in segments.iter().zip(offsets) {
            let start = (offset-min) as usize;
            for (i,&byte) in seg.bytes.iter().enumerate() {
                match data[start+i] { Some(old) => { retransmitted += 1; if old != byte { conflicts += 1; } }, None => data[start+i] = Some(byte) }
            }
        }
        let missing = data.iter().filter(|b| b.is_none()).count();
        directions.push(Direction { label: format!("{}:{} → {}:{}",src.0,src.1,dst.0,dst.1), base_seq: anchor.wrapping_add(min as u32), data, missing, retransmitted, conflicts });
    }
    Ok(Stream { directions, packets: packets.len(), skipped_fragments, truncated_packets })
}
pub fn hex_page(data: &[Option<u8>], offset: usize, count: usize) -> String {
    use std::fmt::Write;
    let mut s = String::from("OFFSET      00 01 02 03 04 05 06 07  08 09 0A 0B 0C 0D 0E 0F  ASCII\n");
    let end = offset.saturating_add(count).min(data.len());
    if offset >= end { return s; }
    for (row, chunk) in data[offset..end].chunks(16).enumerate() {
        let _ = write!(s,"{:08X}    ", offset + row * 16);
        for i in 0..16 { if i == 8 { s.push(' '); } match chunk.get(i) { Some(Some(b)) => { let _ = write!(s,"{b:02X} "); }, Some(None) => s.push_str("?? "), None => s.push_str("   ") } }
        s.push(' '); for b in chunk { s.push(match b { Some(x) if (0x20..=0x7e).contains(x) => *x as char, Some(_) => '.', None => '?' }); } s.push('\n');
    }
    s
}
pub fn text_page(data: &[Option<u8>], offset: usize, count: usize) -> String {
    let end = offset.saturating_add(count).min(data.len());
    if offset >= end { return String::new(); }
    let mut out = String::new(); let mut pos = offset;
    while pos < end {
        let known = data[pos].is_some(); let begin = pos;
        while pos < end && data[pos].is_some() == known { pos += 1; }
        if known {
            let bytes: Vec<u8> = data[begin..pos].iter().map(|b| b.unwrap()).collect();
            out.extend(String::from_utf8_lossy(&bytes).chars().map(|c| if c == '\u{fffd}' || (c.is_control() && c != '\n' && c != '\r' && c != '\t') { '·' } else { c }));
        } else { out.push_str(&format!("\n[missing {} bytes]\n",pos-begin)); }
    }
    out
}
#[cfg(test)] mod tests {
    use super::*;
    fn packet(seq:u32, payload:&[u8], flags:u8) -> Vec<u8> {
        let mut b=vec![0u8;40+payload.len()]; b[0]=0x45; let n=b.len() as u16; b[2..4].copy_from_slice(&n.to_be_bytes()); b[9]=6; b[12..16].copy_from_slice(&[192,0,2,1]); b[16..20].copy_from_slice(&[198,51,100,1]); b[20..22].copy_from_slice(&1234u16.to_be_bytes()); b[22..24].copy_from_slice(&443u16.to_be_bytes()); b[24..28].copy_from_slice(&seq.to_be_bytes()); b[32]=0x50; b[33]=flags; b[40..].copy_from_slice(payload); b
    }
    #[test] fn reorder_retransmit_and_preserve_gaps() {
        let s=build(&[packet(104,b"EF",0),packet(100,b"AB",0),packet(101,b"B",0)]).unwrap(); let d=&s.directions[0];
        assert_eq!(d.data,vec![Some(b'A'),Some(b'B'),None,None,Some(b'E'),Some(b'F')]); assert_eq!(d.retransmitted,1); assert_eq!(d.missing,2);
    }
    #[test] fn syn_and_sequence_wrap() {
        let s=build(&[packet(u32::MAX,b"A",2),packet(1,b"B",0)]).unwrap(); assert_eq!(s.directions[0].base_seq,0); assert_eq!(s.directions[0].data,vec![Some(b'A'),Some(b'B')]);
    }
    #[test] fn conflicting_overlap_keeps_first_observation() {
        let s=build(&[packet(10,b"AB",0),packet(11,b"X",0)]).unwrap();
        assert_eq!(s.directions[0].data,vec![Some(b'A'),Some(b'B')]);
        assert_eq!(s.directions[0].retransmitted,1); assert_eq!(s.directions[0].conflicts,1);
    }
    #[test] fn rejects_excessive_sequence_span() {
        assert!(build(&[packet(1,b"A",0),packet(9_000_000,b"B",0)]).is_err());
    }
    #[test] fn skips_fragments_and_reports_truncation() {
        let mut fragment=packet(1,b"X",0); fragment[6]=0x20;
        let mut truncated=packet(2,b"YZ",0); truncated[2..4].copy_from_slice(&100u16.to_be_bytes());
        let s=build(&[fragment,truncated]).unwrap();
        assert_eq!(s.skipped_fragments,1); assert_eq!(s.truncated_packets,1);
    }
    #[test] fn byte_search_and_paging_use_full_offsets() {
        let d = [Some(b'A'),None,Some(b'B'),Some(b'C')];
        assert!(hex_page(&d, 2, 2).contains("00000002    42 43"));
        assert!(text_page(&d, 0, 4).contains("[missing 1 bytes]"));
    }
    #[test] fn malformed_inputs_do_not_panic() {
        let mut state = 0x12345678u32;
        for len in 0..256 {
            for _ in 0..32 {
                let mut data = vec![0u8; len];
                for byte in &mut data { state ^= state << 13; state ^= state >> 17; state ^= state << 5; *byte = state as u8; }
                if len > 0 { data[0] = 0x45; }
                if len > 9 { data[9] = 6; }
                let _ = build(&[data]);
            }
        }
    }
}
