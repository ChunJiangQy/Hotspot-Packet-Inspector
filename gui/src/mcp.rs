use serde_json::{json, Value};
use std::fs::{self, File};
use std::io::{self, BufRead, Read, Write};
use std::path::{Component, Path, PathBuf};

fn captures(root: &Path) -> PathBuf { root.join("captures") }
fn file_path(root: &Path, file: &str) -> Result<PathBuf, String> {
    let mut components = Path::new(file).components();
    if !matches!(components.next(), Some(Component::Normal(_))) || components.next().is_some() || !file.to_ascii_lowercase().ends_with(".pcap") { return Err("file must be a .pcap filename in the captures folder".into()); }
    let dir = captures(root).canonicalize().map_err(|e| e.to_string())?;
    let path = dir.join(file).canonicalize().map_err(|e| e.to_string())?;
    if path.parent() != Some(dir.as_path()) { return Err("capture file must stay inside captures folder".into()); }
    Ok(path)
}
fn u32le(b: &[u8]) -> u32 { u32::from_le_bytes([b[0], b[1], b[2], b[3]]) }
fn read_packets(path: &Path, offset: usize, count: usize) -> Result<(Vec<Vec<u8>>, bool), String> {
    if offset > 100_000 || count > 50 { return Err("offset must be <= 100000 and count <= 50".into()); }
    let mut f = File::open(path).map_err(|e| e.to_string())?;
    let mut global = [0; 24]; f.read_exact(&mut global).map_err(|e| e.to_string())?;
    if u32le(&global[..4]) != 0xa1b2c3d4 || u32le(&global[20..24]) != 101 { return Err("only little-endian raw-IP PCAP captures are supported".into()); }
    let mut packets = Vec::new();
    for index in 0..offset.saturating_add(count) {
        let mut header = [0u8; 16];
        let mut got = 0;
        while got < header.len() { match f.read(&mut header[got..]) { Ok(0) => return Ok((packets, got != 0)), Ok(n) => got += n, Err(e) => return Err(e.to_string()) } }
        let size = u32le(&header[8..12]) as usize;
        if size > 65535 { return Err("invalid packet length".into()); }
        let mut data = vec![0; size];
        if let Err(e) = f.read_exact(&mut data) { if e.kind() == io::ErrorKind::UnexpectedEof { return Ok((packets, true)); } return Err(e.to_string()); }
        if index >= offset { packets.push(data); }
    }
    Ok((packets, false))
}
fn named_packet(root: &Path, file: &str, index: usize) -> Result<Vec<u8>, String> {
    let (mut packets, _) = read_packets(&file_path(root, file)?, index, 1)?;
    packets.pop().ok_or_else(|| "packet index not available".into())
}
fn tool(root: &Path, name: &str, a: &Value) -> Result<Value, String> {
    match name {
        "capture_status" => {
            let status = fs::read_to_string(root.join("capture-status.json")).ok().and_then(|s| serde_json::from_str::<Value>(&s).ok());
            Ok(json!({"last_reported_gui_status":status,"note":"Status is last reported by the GUI and may be stale after a crash. Active files flush approximately once per second."}))
        }
        "list_captures" => {
            let mut list = Vec::new();
            if let Ok(entries) = fs::read_dir(captures(root)) {
                for entry in entries.flatten() {
                    if let Ok(meta) = entry.metadata() {
                        let name = entry.file_name().to_string_lossy().into_owned();
                        if meta.is_file() && name.to_ascii_lowercase().ends_with(".pcap") { list.push(json!({"file":name,"size_bytes":meta.len()})); }
                    }
                }
            }
            list.sort_by_key(|v| v["file"].as_str().unwrap_or("").to_owned()); list.truncate(200);
            Ok(json!({"captures":list,"limit":200}))
        }
        "read_packets" => {
            let file = a["file"].as_str().ok_or("file is required")?;
            let offset = a["offset"].as_u64().unwrap_or(0) as usize;
            let count = a["count"].as_u64().unwrap_or(10) as usize;
            let max_bytes = (a["max_bytes"].as_u64().unwrap_or(256) as usize).min(4096);
            let (packets, incomplete) = read_packets(&file_path(root, file)?, offset, count)?;
            let result: Vec<_> = packets.iter().enumerate().map(|(n,p)| {
                let info = crate::metadata::parse(p);
                json!({"index":offset+n,"length":p.len(),"summary":info.as_ref().map(|i| &i.description),"category_inferred":info.as_ref().map(|i| i.category),"visible_host":info.as_ref().and_then(|i| i.host.as_ref()),"hex":p.iter().take(max_bytes).map(|b|format!("{b:02X}")).collect::<Vec<_>>().join(" "),"truncated":p.len()>max_bytes})
            }).collect();
            Ok(json!({"file":file,"packets":result,"incomplete_tail":incomplete,"note":"Raw IP packets; domains and protocol classifications do not identify a phone app."}))
        }
        "compare_packets" => {
            let f1 = a["file_a"].as_str().ok_or("file_a is required")?; let f2 = a["file_b"].as_str().ok_or("file_b is required")?;
            let n1 = a["index_a"].as_u64().ok_or("index_a is required")? as usize; let n2 = a["index_b"].as_u64().ok_or("index_b is required")? as usize;
            let left = named_packet(root, f1, n1)?; let right = named_packet(root, f2, n2)?;
            let common = left.len().min(right.len());
            let changes: Vec<usize> = (0..common).filter(|&i| left[i] != right[i]).collect();
            let first = changes.first().copied().or_else(|| if left.len() != right.len() { Some(common) } else { None });
            Ok(json!({"length_a":left.len(),"length_b":right.len(),"equal":left == right,"first_difference_offset":first,"different_bytes_in_overlap":changes.len(),"unmatched_tail_bytes":left.len().abs_diff(right.len()),"first_difference_offsets":changes.into_iter().take(32).collect::<Vec<_>>(),"note":"Compares raw IP packets including headers; not TCP stream reassembly."}))
        }
        _ => Err("unknown tool".into())
    }
}
fn tools() -> Value { json!([
    {"name":"capture_status","description":"Read last GUI capture status (may be stale).","inputSchema":{"type":"object","properties":{}}},
    {"name":"list_captures","description":"List PCAP files in the captures directory.","inputSchema":{"type":"object","properties":{}}},
    {"name":"read_packets","description":"Read raw IP packets from a saved or active PCAP. Packet indexes start at zero.","inputSchema":{"type":"object","properties":{"file":{"type":"string"},"offset":{"type":"integer","minimum":0,"maximum":100000},"count":{"type":"integer","minimum":1,"maximum":50},"max_bytes":{"type":"integer","minimum":1,"maximum":4096}},"required":["file"]}},
    {"name":"compare_packets","description":"Compare two raw IP packets by byte, including headers.","inputSchema":{"type":"object","properties":{"file_a":{"type":"string"},"index_a":{"type":"integer","minimum":0,"maximum":100000},"file_b":{"type":"string"},"index_b":{"type":"integer","minimum":0,"maximum":100000}},"required":["file_a","index_a","file_b","index_b"]}}
]) }
pub fn run(root: &Path) {
    let stdin = io::stdin(); let mut out = io::stdout().lock();
    for line in stdin.lock().lines() {
        let line = match line { Ok(s) => s, Err(_) => break };
        let v: Value = match serde_json::from_str(&line) { Ok(v) => v, Err(_) => { let _ = writeln!(out, "{}", json!({"jsonrpc":"2.0","id":null,"error":{"code":-32700,"message":"Parse error"}})); let _ = out.flush(); continue; } };
        let id = match v.get("id") { Some(id) => id.clone(), None => continue };
        let method = v["method"].as_str().unwrap_or("");
        let result = match method {
            "initialize" => { let requested = v["params"]["protocolVersion"].as_str().unwrap_or(""); let version = if ["2024-11-05","2025-03-26","2025-06-18"].contains(&requested) { requested } else { "2025-03-26" }; Some(json!({"protocolVersion":version,"capabilities":{"tools":{}},"serverInfo":{"name":"packet-tool","version":"1.0.0"}})) },
            "ping" => Some(json!({})),
            "tools/list" => Some(json!({"tools":tools()})),
            "tools/call" => { let name = v["params"]["name"].as_str().unwrap_or(""); let empty = json!({}); let args = v["params"].get("arguments").unwrap_or(&empty); Some(match tool(root,name,args) { Ok(data) => json!({"content":[{"type":"text","text":data.to_string()}]}), Err(e) => json!({"isError":true,"content":[{"type":"text","text":e}]}) }) },
            _ => None,
        };
        let response = match result { Some(value) => json!({"jsonrpc":"2.0","id":id,"result":value}), None => json!({"jsonrpc":"2.0","id":id,"error":{"code":-32601,"message":"Method not found"}}) };
        if writeln!(out, "{response}").and_then(|_| out.flush()).is_err() { break; }
    }
}
