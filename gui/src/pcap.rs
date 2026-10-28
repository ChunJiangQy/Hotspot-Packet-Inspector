use std::collections::VecDeque;
use std::io::{self, Read};
use std::net::Ipv4Addr;

pub struct Loaded { pub packets: VecDeque<(u64, Vec<u8>)>, pub records: u64, pub skipped: u64 }
fn number(data: &[u8], little: bool) -> u32 {
    let b = [data[0], data[1], data[2], data[3]];
    if little { u32::from_le_bytes(b) } else { u32::from_be_bytes(b) }
}
pub fn load<R: Read>(mut input: R, limit: usize) -> Result<Loaded, String> {
    let mut header = [0u8; 24];
    input.read_exact(&mut header).map_err(|_| "Invalid or incomplete PCAP header".to_owned())?;
    let little = match &header[..4] {
        [0xd4, 0xc3, 0xb2, 0xa1] | [0x4d, 0x3c, 0xb2, 0xa1] => true,
        [0xa1, 0xb2, 0xc3, 0xd4] | [0xa1, 0xb2, 0x3c, 0x4d] => false,
        _ => return Err("Unsupported format: select a classic PCAP file (PCAPNG is not supported)".into()),
    };
    let linktype = number(&header[20..24], little) & 0x0000ffff;
    if linktype != 101 && linktype != 1 { return Err(format!("Unsupported PCAP link type {linktype}; raw IP and Ethernet are supported")); }
    let mut result = Loaded { packets: VecDeque::new(), records: 0, skipped: 0 };
    let mut bytes_held = 0usize;
    loop {
        let mut record = [0u8; 16];
        let mut n = 0;
        while n < record.len() {
            match input.read(&mut record[n..]) {
                Ok(0) if n == 0 => return Ok(result),
                Ok(0) => return Err("Incomplete PCAP record header".into()),
                Ok(got) => n += got,
                Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
                Err(e) => return Err(e.to_string()),
            }
        }
        let size = number(&record[8..12], little) as usize;
        if size > 262_144 { return Err("PCAP record exceeds the 256 KiB safety limit".into()); }
        let mut data = vec![0u8; size];
        input.read_exact(&mut data).map_err(|_| "Incomplete PCAP packet".to_owned())?;
        result.records += 1;
        let raw = if linktype == 101 { data.as_slice() } else {
            if data.len() < 14 { result.skipped += 1; continue; }
            let mut offset = 14;
            let mut ethertype = u16::from_be_bytes([data[12], data[13]]);
            while ethertype == 0x8100 || ethertype == 0x88a8 {
                if data.len() < offset + 4 { break; }
                ethertype = u16::from_be_bytes([data[offset + 2], data[offset + 3]]);
                offset += 4;
            }
            if ethertype != 0x0800 || offset > data.len() { result.skipped += 1; continue; }
            &data[offset..]
        };
        if raw.len() < 20 || raw[0] >> 4 != 4 { result.skipped += 1; continue; }
        let total = u16::from_be_bytes([raw[2], raw[3]]) as usize;
        let raw = if total >= 20 && total < raw.len() { &raw[..total] } else { raw };
        bytes_held += raw.len() * 2;
        result.packets.push_back((result.records, raw.to_vec()));
        while result.packets.len() > limit || bytes_held > 16 * 1024 * 1024 {
            if let Some((_, old)) = result.packets.pop_front() { bytes_held -= old.len() * 2; }
        }
    }
}

pub fn flow_key(packet: &[u8]) -> Option<String> {
    if packet.len() < 20 || packet[0] >> 4 != 4 { return None; }
    let src = Ipv4Addr::new(packet[12], packet[13], packet[14], packet[15]);
    let dst = Ipv4Addr::new(packet[16], packet[17], packet[18], packet[19]);
    let ip_header = (packet[0] as usize & 15) * 4;
    if ip_header < 20 || ip_header > packet.len() { return None; }
    let proto = packet[9];
    let fragment = u16::from_be_bytes([packet[6], packet[7]]) & 0x1fff != 0;
    let ports = if !fragment && (proto == 6 || proto == 17) && packet.len() >= ip_header + 4 {
        (u16::from_be_bytes([packet[ip_header], packet[ip_header + 1]]), u16::from_be_bytes([packet[ip_header + 2], packet[ip_header + 3]]))
    } else { (0, 0) };
    let mut endpoints = [(src, ports.0), (dst, ports.1)]; endpoints.sort();
    let label = match proto { 6 => "TCP".to_owned(), 17 => "UDP".to_owned(), 1 => "ICMP".to_owned(), n => format!("IP {n}") };
    Some(if ports == (0, 0) { format!("{label}  {} ↔ {}", endpoints[0].0, endpoints[1].0) }
         else { format!("{label}  {}:{} ↔ {}:{}", endpoints[0].0, endpoints[0].1, endpoints[1].0, endpoints[1].1) })
}

#[cfg(test)]
mod tests {
    use super::*;
    fn packet(a: [u8;4], b: [u8;4], p: u16, q: u16) -> Vec<u8> {
        let mut x = vec![0u8; 28]; x[0]=0x45; x[2..4].copy_from_slice(&28u16.to_be_bytes()); x[9]=17;
        x[12..16].copy_from_slice(&a); x[16..20].copy_from_slice(&b); x[20..22].copy_from_slice(&p.to_be_bytes()); x[22..24].copy_from_slice(&q.to_be_bytes()); x
    }
    #[test] fn opposite_directions_share_flow() {
        let a = packet([192,0,2,1],[198,51,100,2],123,443);
        let b = packet([198,51,100,2],[192,0,2,1],443,123);
        assert_eq!(flow_key(&a), flow_key(&b));
    }
    #[test] fn loads_tail_and_rejects_truncation() {
        let p = packet([192,0,2,1],[198,51,100,2],123,443);
        let mut data = vec![0xd4,0xc3,0xb2,0xa1,2,0,4,0,0,0,0,0,0,0,0,0,0xff,0xff,0,0,101,0,0,0];
        for _ in 0..3 { data.extend_from_slice(&[0;8]); data.extend_from_slice(&(p.len() as u32).to_le_bytes()); data.extend_from_slice(&(p.len() as u32).to_le_bytes()); data.extend_from_slice(&p); }
        let result = load(data.as_slice(), 2).unwrap(); assert_eq!(result.records, 3); assert_eq!(result.packets.front().unwrap().0, 2);
        data.pop(); assert!(load(data.as_slice(), 2).is_err());
    }
    #[test] fn loads_big_endian_ethernet_ipv4_and_skips_ipv6() {
        let p = packet([192,0,2,1],[198,51,100,2],123,443);
        let mut data = vec![0xa1,0xb2,0xc3,0xd4,0,2,0,4,0,0,0,0,0,0,0,0,0,0,0xff,0xff,0,0,0,1];
        let mut ethernet = vec![0u8;14]; ethernet[12]=0x08; ethernet[13]=0x00; ethernet.extend_from_slice(&p);
        for frame in [&ethernet[..], &[0u8;14][..]] {
            data.extend_from_slice(&[0;8]); data.extend_from_slice(&(frame.len() as u32).to_be_bytes()); data.extend_from_slice(&(frame.len() as u32).to_be_bytes()); data.extend_from_slice(frame);
        }
        let result = load(data.as_slice(), 10).unwrap();
        assert_eq!(result.records, 2); assert_eq!(result.skipped, 1); assert_eq!(result.packets[0].1, p);
    }
}
