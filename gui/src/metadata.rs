use std::net::Ipv4Addr;

pub struct Info {
    pub description: String,
    pub details: String,
    pub category: &'static str,
    pub host: Option<String>,
    pub addresses: [Ipv4Addr; 2],
    pub dns_answers: Vec<(Ipv4Addr, String)>,
}

fn u16_at(b: &[u8], n: usize) -> Option<usize> { Some(u16::from_be_bytes([*b.get(n)?, *b.get(n + 1)?]) as usize) }
pub fn payload_offset(packet: &[u8]) -> Option<usize> {
    if packet.len() < 20 || packet[0] >> 4 != 4 || (u16_at(packet, 6)? & 0x1fff) != 0 { return None; }
    let h = (packet[0] as usize & 15) * 4;
    if h < 20 || h > packet.len() { return None; }
    let transport = match packet[9] {
        6 => { let size = (*packet.get(h + 12)? as usize >> 4) * 4; if size < 20 { return None; } size },
        17 => 8,
        _ => return None,
    };
    let result = h.checked_add(transport)?;
    if result <= packet.len() { Some(result) } else { None }
}
fn name(b: &[u8], pos: &mut usize) -> Option<String> {
    let mut labels = Vec::new();
    let mut cursor = *pos;
    let mut end = None;
    for _ in 0..128 {
        let len = *b.get(cursor)? as usize;
        if len & 0xc0 == 0xc0 {
            let target = ((len & 0x3f) << 8) | *b.get(cursor + 1)? as usize;
            if end.is_none() { end = Some(cursor + 2); }
            cursor = target;
        } else if len == 0 {
            *pos = end.unwrap_or(cursor + 1);
            return if labels.is_empty() { None } else { Some(labels.join(".")) };
        } else {
            if len > 63 { return None; }
            let label = std::str::from_utf8(b.get(cursor + 1..cursor + 1 + len)?).ok()?;
            labels.push(label.to_owned());
            cursor += 1 + len;
        }
    }
    None
}

fn dns(data: &[u8]) -> Option<(String, Vec<(Ipv4Addr, String)>)> {
    if data.len() < 12 || u16_at(data, 4)? == 0 { return None; }
    let mut p = 12;
    let query = name(data, &mut p)?;
    p = p.checked_add(4)?;
    let mut answers = Vec::new();
    for _ in 1..u16_at(data, 4)?.min(64) { name(data, &mut p)?; p = p.checked_add(4)?; }
    if data[2] & 0x80 != 0 {
        for _ in 0..u16_at(data, 6)?.min(256) {
            name(data, &mut p)?;
            let typ = u16_at(data, p)?;
            let class = u16_at(data, p + 2)?;
            let size = u16_at(data, p + 8)?;
            p = p.checked_add(10)?;
            let value = data.get(p..p.checked_add(size)?)?;
            if typ == 1 && class == 1 && size == 4 { answers.push((Ipv4Addr::new(value[0], value[1], value[2], value[3]), query.clone())); }
            p += size;
        }
    }
    Some((query, answers))
}

fn tls_sni(data: &[u8]) -> Option<String> {
    if data.len() < 9 || data[0] != 22 || data[5] != 1 { return None; }
    let record_len = u16_at(data, 3)?;
    let data = data.get(..5 + record_len)?;
    let mut p = 9 + 2 + 32;
    p += 1 + *data.get(p)? as usize;
    p += 2 + u16_at(data, p)?;
    p += 1 + *data.get(p)? as usize;
    let end = p.checked_add(2 + u16_at(data, p)?)?;
    p += 2;
    if end > data.len() { return None; }
    while p + 4 <= end {
        let typ = u16_at(data, p)?;
        let len = u16_at(data, p + 2)?;
        p += 4;
        let extension = data.get(p..p.checked_add(len)?)?;
        if typ == 0 && extension.get(2) == Some(&0) {
            let n = u16_at(extension, 3)?;
            return Some(std::str::from_utf8(extension.get(5..5 + n)?).ok()?.to_owned());
        }
        p += len;
    }
    None
}

pub fn parse(packet: &[u8]) -> Option<Info> {
    if packet.len() < 20 || packet[0] >> 4 != 4 { return None; }
    let h = (packet[0] as usize & 15) * 4;
    if h < 20 || h > packet.len() { return None; }
    let src = Ipv4Addr::new(packet[12], packet[13], packet[14], packet[15]);
    let dst = Ipv4Addr::new(packet[16], packet[17], packet[18], packet[19]);
    let protocol = packet[9];
    let mut description = format!("{src} → {dst}  IPv4");
    let mut details = format!("来源 IP：{src}\n目标 IP：{dst}\nIP 包长：{} 字节\nIP 头长：{h} 字节\nTTL：{}\n协议号：{protocol}", packet.len(), packet[8]);
    let mut category = if protocol == 1 { "ICMP" } else { "其他" };
    let mut host = None;
    let mut dns_answers = Vec::new();
    if (protocol == 6 || protocol == 17) && packet.len() >= h + 8 && (u16_at(packet, 6)? & 0x1fff) == 0 {
        let sp = u16_at(packet, h)?;
        let dp = u16_at(packet, h + 2)?;
        category = if protocol == 6 { "TCP" } else { "UDP" };
        description = format!("{src}:{sp} → {dst}:{dp}  {}", if protocol == 6 { "TCP" } else { "UDP" });
        let transport_len = if protocol == 6 { (*packet.get(h + 12)? as usize >> 4) * 4 } else { 8 };
        if transport_len < if protocol == 6 { 20 } else { 8 } { return None; }
        let payload = packet.get(h + transport_len..)?;
        details.push_str(&format!("\n来源端口：{sp}\n目标端口：{dp}\n传输协议：{}\n传输头长：{transport_len} 字节\n本包载荷：{} 字节", if protocol == 6 { "TCP" } else { "UDP" }, payload.len()));
        if protocol == 6 {
            let flags = *packet.get(h + 13)?;
            let mut names = Vec::new();
            for (mask, name) in [(0x01, "FIN"), (0x02, "SYN"), (0x04, "RST"), (0x08, "PSH"), (0x10, "ACK"), (0x20, "URG")] { if flags & mask != 0 { names.push(name); } }
            details.push_str(&format!("\nTCP 标志：{}", if names.is_empty() { "无".to_owned() } else { names.join(", ") }));
        }
        if protocol == 17 && (sp == 53 || dp == 53) {
            category = "DNS";
            if let Some((query, answers)) = dns(payload) { host = Some(format!("DNS: {query}")); dns_answers = answers; }
        } else if protocol == 6 {
            if sp == 53 || dp == 53 { category = "DNS"; }
            else if sp == 443 || dp == 443 { category = "TLS/HTTPS（可能）"; }
            else if sp == 80 || dp == 80 || sp == 8080 || dp == 8080 { category = "HTTP（可能）"; }
            if let Some(sni) = tls_sni(payload) { category = "TLS/HTTPS（可能）"; host = Some(format!("TLS SNI: {sni}")); }
            else if let Ok(text) = std::str::from_utf8(payload) {
                if let Some(line) = text.lines().find(|line| line.get(..5).map_or(false, |prefix| prefix.eq_ignore_ascii_case("host:"))) {
                    category = "HTTP（可能）";
                    host = Some(format!("HTTP Host: {}", line[5..].trim()));
                }
            }
        } else if sp == 443 || dp == 443 {
            category = "UDP 443（可能为 QUIC）";
        }
    }
    Some(Info { description, details, category, host, addresses: [src, dst], dns_answers })
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn dns_compressed_answer() {
        let msg = [0x12,0x34,0x81,0x80,0,1,0,1,0,0,0,0, 3,b'w',b'w',b'w',7,b'e',b'x',b'a',b'm',b'p',b'l',b'e',3,b'c',b'o',b'm',0, 0,1,0,1, 0xc0,0x0c,0,1,0,1,0,0,0,60,0,4,1,2,3,4];
        let (host, answers) = dns(&msg).unwrap();
        assert_eq!(host, "www.example.com");
        assert_eq!(answers[0].0, Ipv4Addr::new(1,2,3,4));
    }
    #[test]
    fn rejects_dns_pointer_loop() { let mut p = 0; assert!(name(&[0xc0,0], &mut p).is_none()); }
    #[test]
    fn classifies_udp_by_port_and_reports_endpoints() {
        let mut packet = [0u8; 28];
        packet[0] = 0x45; packet[8] = 64; packet[9] = 17;
        packet[12..16].copy_from_slice(&[192, 0, 2, 10]);
        packet[16..20].copy_from_slice(&[198, 51, 100, 5]);
        packet[20..24].copy_from_slice(&[0x30, 0x39, 0x01, 0xbb]);
        let info = parse(&packet).unwrap();
        assert_eq!(info.category, "UDP 443（可能为 QUIC）");
        assert!(info.description.contains("192.0.2.10:12345 → 198.51.100.5:443"));
        assert_eq!(payload_offset(&packet), Some(28));
    }
}
