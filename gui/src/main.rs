#![windows_subsystem = "windows"]
mod metadata;
mod mcp;
mod pcap;

use eframe::egui::{self, Color32, FontData, FontDefinitions, FontFamily, RichText};
use std::fs;
use std::collections::{HashMap, VecDeque};
use std::io::{BufRead, BufReader};
use std::os::windows::ffi::{OsStrExt, OsStringExt};
use std::os::windows::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::mpsc::{self, Receiver};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

#[link(name = "shell32")]
extern "system" {
    fn IsUserAnAdmin() -> i32;
    fn ShellExecuteW(hwnd: isize, operation: *const u16, file: *const u16, params: *const u16, dir: *const u16, show: i32) -> isize;
}
#[link(name = "user32")]
extern "system" { fn MessageBoxW(hwnd: isize, text: *const u16, caption: *const u16, flags: u32) -> i32; }
#[repr(C)]
struct OpenFileName {
    size: u32, owner: isize, instance: isize, filter: *const u16, custom_filter: *mut u16,
    custom_filter_size: u32, filter_index: u32, file: *mut u16, max_file: u32,
    file_title: *mut u16, max_file_title: u32, initial_dir: *const u16, title: *const u16,
    flags: u32, file_offset: u16, extension_offset: u16, default_ext: *const u16,
    custom_data: isize, hook: isize, template: *const u16, reserved: *mut std::ffi::c_void,
    reserved_u32: u32, flags_ex: u32,
}
#[link(name = "comdlg32")]
extern "system" { fn GetOpenFileNameW(ofn: *mut OpenFileName) -> i32; }
fn choose_pcap() -> Option<PathBuf> {
    let filter: Vec<u16> = "PCAP files (*.pcap)\0*.pcap\0All files (*.*)\0*.*\0\0".encode_utf16().collect();
    let mut path = vec![0u16; 32768];
    let mut dialog: OpenFileName = unsafe { std::mem::zeroed() };
    dialog.size = std::mem::size_of::<OpenFileName>() as u32;
    dialog.filter = filter.as_ptr(); dialog.file = path.as_mut_ptr(); dialog.max_file = path.len() as u32;
    dialog.flags = 0x0008 | 0x0800 | 0x1000 | 0x80000;
    if unsafe { GetOpenFileNameW(&mut dialog) } == 0 { return None; }
    let len = path.iter().position(|&x| x == 0)?;
    Some(PathBuf::from(std::ffi::OsString::from_wide(&path[..len])))
}

fn wide(s: &std::ffi::OsStr) -> Vec<u16> { s.encode_wide().chain(Some(0)).collect() }
fn message(s: &str) {
    unsafe { MessageBoxW(0, wide(s.as_ref()).as_ptr(), wide("PacketTool".as_ref()).as_ptr(), 0x10); }
}

fn main() -> eframe::Result {
    let exe = match std::env::current_exe() { Ok(p) => p, Err(e) => { message(&e.to_string()); return Ok(()); } };
    if std::env::args().nth(1).as_deref() == Some("--mcp") {
        mcp::run(exe.parent().unwrap_or(Path::new(".")));
        return Ok(());
    }
    if unsafe { IsUserAnAdmin() } == 0 {
        let result = unsafe { ShellExecuteW(0, wide("runas".as_ref()).as_ptr(), wide(exe.as_os_str()).as_ptr(), std::ptr::null(), std::ptr::null(), 1) };
        if result <= 32 { message("无法获得管理员权限，无法启动抓包。请重新启动并允许管理员权限。"); }
        return Ok(());
    }
    let root = exe.parent().unwrap_or(Path::new(".")).to_path_buf();
    let options = eframe::NativeOptions { viewport: egui::ViewportBuilder::default().with_inner_size([1100.0, 720.0]).with_min_inner_size([820.0, 560.0]).with_resizable(true), ..Default::default() };
    eframe::run_native("PacketTool - 热点抓包", options, Box::new(move |cc| {
        let mut fonts = FontDefinitions::default();
        if let Ok(data) = fs::read("C:\\Windows\\Fonts\\segoeui.ttf") {
            fonts.font_data.insert("windows-ui".into(), FontData::from_owned(data).into());
            fonts.families.entry(FontFamily::Proportional).or_default().insert(0, "windows-ui".into());
        }
        if let Ok(data) = fs::read("C:\\Windows\\Fonts\\consola.ttf") {
            fonts.font_data.insert("windows-mono".into(), FontData::from_owned(data).into());
            fonts.families.entry(FontFamily::Monospace).or_default().insert(0, "windows-mono".into());
        }
        for path in ["C:\\Windows\\Fonts\\msyh.ttc", "C:\\Windows\\Fonts\\simhei.ttf"] {
            if let Ok(data) = fs::read(path) {
                fonts.font_data.insert("chinese".into(), FontData::from_owned(data).into());
                fonts.families.entry(FontFamily::Proportional).or_default().push("chinese".into());
                fonts.families.entry(FontFamily::Monospace).or_default().push("chinese".into());
                break;
            }
        }
        cc.egui_ctx.set_fonts(fonts);
        cc.egui_ctx.style_mut(|style| {
            style.spacing.item_spacing = egui::vec2(10.0, 8.0);
            style.spacing.button_padding = egui::vec2(13.0, 7.0);
            style.spacing.window_margin = egui::Margin::same(18);
            style.spacing.interact_size.y = 30.0;
        });
        let app = CaptureApp::new(root);
        apply_theme(&cc.egui_ctx, app.settings.dark);
        cc.egui_ctx.set_zoom_factor(app.settings.zoom);
        Ok(Box::new(app))
    }))
}

enum Event { Line(String), Finished(String), Imported(PathBuf, Result<pcap::Loaded, String>) }
#[derive(Clone, PartialEq)]
struct Settings { dark: bool, english: bool, zoom: f32, font_size: f32, packet_limit: usize }
impl Default for Settings {
    fn default() -> Self { Self { dark: false, english: false, zoom: 1.0, font_size: 13.0, packet_limit: 500 } }
}
impl Settings {
    fn load(path: &Path) -> Self {
        let mut s = Self::default();
        if let Ok(data) = fs::read_to_string(path) {
            for line in data.lines() {
                if let Some((key, value)) = line.split_once('=') {
                    match key {
                        "theme" => s.dark = value == "dark",
                        "language" => s.english = value == "en",
                        "zoom" => if let Ok(n) = value.parse::<f32>() { if n.is_finite() { s.zoom = n.clamp(0.8, 1.5); } },
                        "font_size" => if let Ok(n) = value.parse::<f32>() { if n.is_finite() { s.font_size = n.clamp(11.0, 20.0); } },
                        "packet_limit" => if let Ok(n) = value.parse::<usize>() { s.packet_limit = n.clamp(100, 2000); },
                        _ => {}
                    }
                }
            }
        }
        s
    }
    fn save(&self, path: &Path) -> std::io::Result<()> {
        fs::write(path, format!("theme={}\nlanguage={}\nzoom={}\nfont_size={}\npacket_limit={}\n", if self.dark { "dark" } else { "light" }, if self.english { "en" } else { "zh" }, self.zoom, self.font_size, self.packet_limit))
    }
}
fn tr<'a>(en: bool, zh: &'a str, english: &'a str) -> &'a str { if en { english } else { zh } }
fn apply_theme(ctx: &egui::Context, dark: bool) {
    let mut v = if dark { egui::Visuals::dark() } else { egui::Visuals::light() };
    if dark {
        v.panel_fill = Color32::from_rgb(15, 20, 30); v.window_fill = Color32::from_rgb(24, 32, 45);
        v.extreme_bg_color = Color32::from_rgb(11, 16, 24); v.faint_bg_color = Color32::from_rgb(24, 33, 47);
        v.widgets.noninteractive.bg_fill = Color32::from_rgb(24, 33, 47); v.widgets.inactive.bg_fill = Color32::from_rgb(31, 43, 59);
        v.widgets.hovered.bg_fill = Color32::from_rgb(42, 60, 81); v.selection.bg_fill = Color32::from_rgb(27, 83, 117);
        v.selection.stroke.color = Color32::from_rgb(93, 207, 219);
    } else {
        v.panel_fill = Color32::from_rgb(243, 246, 250); v.window_fill = Color32::from_rgb(249, 250, 252);
        v.extreme_bg_color = Color32::WHITE; v.faint_bg_color = Color32::from_rgb(234, 239, 245);
        v.widgets.noninteractive.bg_stroke = egui::Stroke::new(1.0, Color32::from_rgb(225, 230, 236));
        v.widgets.inactive.bg_fill = Color32::WHITE; v.widgets.inactive.bg_stroke = egui::Stroke::new(1.0, Color32::from_rgb(210, 218, 227));
        v.widgets.hovered.bg_fill = Color32::from_rgb(239, 245, 251);
        v.selection.bg_fill = Color32::from_rgb(215, 235, 250); v.selection.stroke.color = Color32::from_rgb(0, 103, 192);
    }
    v.window_corner_radius = egui::CornerRadius::same(10);
    v.menu_corner_radius = egui::CornerRadius::same(6);
    v.widgets.inactive.corner_radius = egui::CornerRadius::same(5);
    v.widgets.hovered.corner_radius = egui::CornerRadius::same(5);
    v.widgets.active.corner_radius = egui::CornerRadius::same(5);
    ctx.set_visuals(v);
}
fn local_category<'a>(en: bool, category: &'a str) -> &'a str {
    if !en { return category; }
    match category { "全部" => "All", "HTTP（可能）" => "HTTP (possible)", "TLS/HTTPS（可能）" => "TLS/HTTPS (possible)", "UDP 443（可能为 QUIC）" => "UDP 443 (possible QUIC)", "其他" => "Other", _ => category }
}
fn settings_card(ui: &mut egui::Ui, dark: bool, title: &str, description: &str, controls: impl FnOnce(&mut egui::Ui)) {
    egui::Frame::new()
        .fill(if dark { Color32::from_rgb(36, 38, 42) } else { Color32::WHITE })
        .stroke(egui::Stroke::new(1.0, if dark { Color32::from_rgb(59, 62, 68) } else { Color32::from_rgb(226, 230, 235) }))
        .corner_radius(7).inner_margin(egui::Margin::same(14))
        .show(ui, |ui| {
            ui.set_min_width(ui.available_width());
            ui.horizontal(|ui| {
                ui.vertical(|ui| {
                    ui.label(RichText::new(title).strong().size(14.0));
                    ui.label(RichText::new(description).size(12.0).color(if dark { Color32::from_rgb(168, 174, 183) } else { Color32::from_rgb(100, 110, 122) }));
                });
                ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| { controls(ui); });
            });
        });
}
fn translate_detail(s: &str) -> String {
    let mut text = s.to_owned();
    for (zh, en) in [("来源 IP", "Source IP"), ("目标 IP", "Destination IP"), ("IP 包长", "IP packet length"), ("IP 头长", "IP header length"), ("来源端口", "Source port"), ("目标端口", "Destination port"), ("传输协议", "Transport protocol"), ("传输头长", "Transport header length"), ("本包载荷", "Packet payload"), ("TCP 标志", "TCP flags"), ("协议号", "Protocol number"), ("DNS 关联（可能不唯一）", "DNS association (may be shared)"), ("字节", "bytes"), ("无", "None")] { text = text.replace(zh, en); }
    text
}
struct Packet { id: u64, summary: String, hex: String, detail: String, category: &'static str, info: String, protocol: u8, flow: Option<String> }
fn matches_filter(packet: &Packet, filter: &str, search: &str) -> bool {
    let category_matches = match filter { "全部" => true, "TCP" => packet.protocol == 6, "UDP" => packet.protocol == 17, other => packet.category == other };
    category_matches && (search.is_empty() || packet.summary.to_lowercase().contains(search))
}

fn decode_hex(hex: &str) -> Vec<u8> {
    hex.as_bytes().chunks_exact(2).filter_map(|pair| std::str::from_utf8(pair).ok().and_then(|s| u8::from_str_radix(s, 16).ok())).collect()
}
fn render_hex_at(bytes: &[u8], offset: usize) -> String {
    use std::fmt::Write;
    let mut result = String::from("OFFSET      00 01 02 03 04 05 06 07  08 09 0A 0B 0C 0D 0E 0F  ASCII\n");
    for (row, chunk) in bytes.chunks(16).enumerate() {
        let _ = write!(result, "{:08X}    ", offset + row * 16);
        for i in 0..16 {
            if i == 8 { result.push(' '); }
            if let Some(byte) = chunk.get(i) { let _ = write!(result, "{byte:02X} "); } else { result.push_str("   "); }
        }
        result.push(' ');
        for &byte in chunk { result.push(if (0x20..=0x7e).contains(&byte) { byte as char } else { '.' }); }
        result.push('\n');
    }
    result
}
#[cfg(test)]
fn render_hex(bytes: &[u8]) -> String { render_hex_at(bytes, 0) }
fn render_text(bytes: &[u8]) -> String {
    String::from_utf8_lossy(bytes).chars().map(|c| {
        if c == '\u{fffd}' || (c.is_control() && c != '\n' && c != '\r' && c != '\t') { '·' } else { c }
    }).collect()
}
fn category_color(category: &str) -> Color32 {
    match category {
        "DNS" => Color32::from_rgb(106, 205, 220),
        "HTTP（可能）" => Color32::from_rgb(243, 186, 105),
        "TLS/HTTPS（可能）" => Color32::from_rgb(150, 177, 250),
        "UDP 443（可能为 QUIC）" => Color32::from_rgb(194, 155, 239),
        "TCP" => Color32::from_rgb(130, 206, 161),
        "UDP" => Color32::from_rgb(231, 182, 136),
        _ => Color32::from_rgb(157, 174, 192),
    }
}
struct CaptureApp {
    root: PathBuf,
    folder: PathBuf,
    duration: String,
    ip: String,
    log: String,
    state: String,
    receiver: Option<Receiver<Event>>,
    stop_file: Option<PathBuf>,
    last_file: Option<PathBuf>,
    packets: VecDeque<Packet>,
    packet_bytes: usize,
    packet_count: u64,
    selected: Option<u64>,
    text_view: bool,
    dns_cache: HashMap<std::net::Ipv4Addr, String>,
    filter: String,
    search: String,
    show_log: bool,
    show_settings: bool,
    settings: Settings,
    show_compare: bool,
    compare_a: Option<(u64, Vec<u8>)>,
    compare_b: Option<(u64, Vec<u8>)>,
    payload_only: bool,
    imported: bool,
    skipped: u64,
    show_flows: bool,
    selected_flow: Option<String>,
}
impl CaptureApp {
    fn new(root: PathBuf) -> Self {
        let settings = Settings::load(&root.join("settings.ini"));
        Self { folder: root.join("captures"), root, duration: "60".into(), ip: String::new(), log: String::new(), state: "准备就绪".into(), receiver: None, stop_file: None, last_file: None, packets: VecDeque::new(), packet_bytes: 0, packet_count: 0, selected: None, text_view: false, dns_cache: HashMap::new(), filter: "全部".into(), search: String::new(), show_log: false, show_settings: false, settings, show_compare: false, compare_a: None, compare_b: None, payload_only: false, imported: false, skipped: 0, show_flows: false, selected_flow: None }
    }
    fn report_status(&self, status: &str) {
        let file = self.last_file.as_ref().and_then(|p| p.file_name()).map(|p| p.to_string_lossy().into_owned());
        let value = serde_json::json!({"state":status,"file":file,"gui_pid":std::process::id()});
        let _ = fs::write(self.root.join("capture-status.json"), value.to_string());
    }
    fn push_packet(&mut self, id: u64, hex: &str) {
        let bytes = decode_hex(hex);
        let mut detail = format!("{} 字节", bytes.len());
        let mut category = "其他";
        let mut info_text = String::new();
        if let Some(info) = metadata::parse(&bytes) {
            if self.dns_cache.len() > 4096 { self.dns_cache.clear(); }
            for (addr, domain) in info.dns_answers { self.dns_cache.insert(addr, domain); }
            category = info.category; info_text = info.details; detail = info.description;
            if let Some(host) = info.host { detail.push_str(&format!("  |  {host}")); info_text.push_str(&format!("\n{host}")); }
            else if let Some(domain) = info.addresses.iter().find_map(|ip| self.dns_cache.get(ip)) { detail.push_str(&format!("  |  DNS 关联（可能不唯一）: {domain}")); info_text.push_str(&format!("\nDNS 关联（可能不唯一）：{domain}")); }
        }
        let summary = format!("#{id}  [{category}]  {detail}");
        self.packet_bytes += hex.len();
        self.packets.push_back(Packet { id, summary, hex: hex.to_owned(), detail, category, info: info_text, protocol: bytes.get(9).copied().unwrap_or(0), flow: pcap::flow_key(&bytes) });
        if self.selected.is_none() { self.selected = Some(id); }
        while self.packets.len() > self.settings.packet_limit || self.packet_bytes > 16 * 1024 * 1024 {
            if let Some(old) = self.packets.pop_front() { self.packet_bytes -= old.hex.len(); if self.selected == Some(old.id) { self.selected = self.packets.front().map(|p| p.id); } }
        }
    }
    fn open_capture(&mut self, path: PathBuf) {
        let limit = self.settings.packet_limit;
        let (tx, rx) = mpsc::channel();
        std::thread::spawn(move || {
            let result = std::fs::File::open(&path).map_err(|e| e.to_string()).and_then(|f| pcap::load(std::io::BufReader::new(f), limit));
            let _ = tx.send(Event::Imported(path, result));
        });
        self.state = "正在打开 PCAP…".into(); self.receiver = Some(rx);
    }
    fn start(&mut self) {
        let seconds: u32 = match self.duration.trim().parse() { Ok(n) if n <= 86400 => n, _ => { self.state = "时长请输入 0 到 86400 秒".into(); return; } };
        let ip = self.ip.trim();
        if !ip.is_empty() && ip.parse::<std::net::Ipv4Addr>().is_err() { self.state = "请输入有效的 IPv4 地址".into(); return; }
        if let Err(e) = fs::create_dir_all(&self.folder) { self.state = format!("无法创建输出目录: {e}"); return; }
        let id = SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().as_millis();
        let output = self.folder.join(format!("hotspot-{id}.pcap"));
        let stop = self.folder.join(format!(".stop-{id}"));
        let exe = self.root.join("windivert").join("WinDivert-2.2.2-A").join("x64").join("PacketTool.exe");
        let mut command = Command::new(exe);
        command.arg("capture").arg(&output).arg("--hotspot").arg("--duration").arg(seconds.to_string()).arg("--stats").arg("5").arg("--stop-file").arg(&stop).arg("--hex-output");
        if !ip.is_empty() { command.arg("--ip").arg(ip); }
        command.stdout(Stdio::piped()).stderr(Stdio::null()).creation_flags(0x08000000);
        let mut child = match command.spawn() { Ok(p) => p, Err(e) => { self.state = format!("启动失败: {e}"); return; } };
        let stdout = child.stdout.take().unwrap();
        let (tx, rx) = mpsc::channel();
        let stop_for_thread = stop.clone();
        std::thread::spawn(move || {
            for line in BufReader::new(stdout).lines() {
                match line { Ok(line) => { let _ = tx.send(Event::Line(line)); }, Err(e) => { let _ = tx.send(Event::Line(format!("读取日志失败: {e}"))); break; } }
            }
            let result = match child.wait() { Ok(s) if s.success() => "抓包完成".to_owned(), Ok(s) => format!("抓包失败: {s}"), Err(e) => format!("等待抓包进程失败: {e}") };
            let _ = fs::remove_file(stop_for_thread);
            let _ = tx.send(Event::Finished(result));
        });
        self.log.clear(); self.packets.clear(); self.dns_cache.clear(); self.compare_a = None; self.compare_b = None; self.packet_bytes = 0; self.packet_count = 0; self.selected = None; self.selected_flow = None; self.imported = false; self.skipped = 0; self.state = "正在抓取热点转发流量…".into();
        self.last_file = Some(output); self.stop_file = Some(stop); self.receiver = Some(rx); self.report_status("capturing");
    }
    fn stop(&mut self) {
        if let Some(path) = &self.stop_file {
            match fs::write(path, b"stop") { Ok(()) => self.state = "正在停止并保存…".into(), Err(e) => self.state = format!("停止失败: {e}") }
        }
    }
}
impl eframe::App for CaptureApp {
    fn update(&mut self, ctx: &egui::Context, _: &mut eframe::Frame) {
        let mut finished = None;
        let mut events = Vec::new();
        if let Some(rx) = &self.receiver {
            while let Ok(event) = rx.try_recv() { events.push(event); }
            ctx.request_repaint_after(Duration::from_millis(250));
        }
        for event in events {
                match event {
                    Event::Line(line) => {
                        if let Some(hex) = line.strip_prefix("PACKET_HEX:") {
                            self.packet_count += 1;
                            self.push_packet(self.packet_count, hex);
                        } else {
                            self.log.push_str(&line); self.log.push('\n');
                            if self.log.len() > 200_000 { self.log.clear(); }
                        }
                    },
                    Event::Finished(s) => finished = Some(s),
                    Event::Imported(path, result) => {
                        self.receiver = None;
                        match result {
                            Ok(loaded) => {
                                self.packets.clear(); self.dns_cache.clear(); self.compare_a = None; self.compare_b = None;
                                self.packet_bytes = 0; self.selected = None; self.selected_flow = None;
                                self.packet_count = loaded.records; self.skipped = loaded.skipped; self.imported = true;
                                self.last_file = Some(path);
                                for (id, data) in loaded.packets {
                                    use std::fmt::Write;
                                    let mut hex = String::with_capacity(data.len() * 2);
                                    for byte in data { let _ = write!(hex, "{byte:02X}"); }
                                    self.push_packet(id, &hex);
                                }
                                self.state = "PCAP 已打开".into();
                            },
                            Err(error) => self.state = format!("打开 PCAP 失败: {error}"),
                        }
                    }
                }
        }
        if let Some(s) = finished { let status = if s == "抓包完成" { "completed" } else { "failed" }; self.state = s; self.receiver = None; self.stop_file = None; self.report_status(status); }
        if ctx.input(|i| i.viewport().close_requested()) && self.stop_file.is_some() { self.stop(); self.report_status("stopping"); }
        let en = self.settings.english;
        let dark = self.settings.dark;
        let muted = if dark { Color32::from_rgb(159, 177, 197) } else { Color32::from_rgb(80, 100, 120) };
        let card = if dark { Color32::from_rgb(21, 29, 41) } else { Color32::WHITE };
        let selected_card = if dark { Color32::from_rgb(27, 65, 83) } else { Color32::from_rgb(215, 235, 248) };
        if !ctx.wants_keyboard_input() && !self.show_settings && !self.show_compare && !self.show_log {
            let direction = ctx.input(|i| if i.key_pressed(egui::Key::ArrowDown) { 1 } else if i.key_pressed(egui::Key::ArrowUp) { -1 } else { 0 });
            if direction != 0 {
                let search = self.search.to_lowercase();
                let ids: Vec<u64> = self.packets.iter().filter(|p| matches_filter(p, &self.filter, &search) && self.selected_flow.as_ref().map_or(true, |key| p.flow.as_ref() == Some(key))).map(|p| p.id).collect();
                if !ids.is_empty() {
                    let current = self.selected.and_then(|id| ids.iter().position(|&x| x == id));
                    let index = match (current, direction) { (Some(i), 1) => (i + 1).min(ids.len() - 1), (Some(i), _) => i.saturating_sub(1), (None, _) => 0 };
                    self.selected = Some(ids[index]);
                }
            }
        }
        egui::TopBottomPanel::top("toolbar").show(ctx, |ui| {
            ui.add_space(3.0);
            ui.horizontal_wrapped(|ui| {
                ui.label(RichText::new("PacketTool").size(19.0).strong().color(if dark { Color32::from_rgb(162, 204, 255) } else { Color32::from_rgb(0, 95, 184) }));
                ui.label(RichText::new(tr(en,"热点流量分析","Hotspot traffic analyzer")).color(muted)); ui.separator();
                let start_button = egui::Button::new(RichText::new(tr(en,"开始抓包","Start capture")).strong().color(Color32::WHITE)).fill(Color32::from_rgb(0, 103, 192));
                if ui.add_enabled(self.receiver.is_none(), start_button).clicked() { self.start(); }
                if ui.add_enabled(self.stop_file.is_some(), egui::Button::new(tr(en,"■ 停止并保存","■ Stop & save"))).clicked() { self.stop(); }
                if ui.add_enabled(self.receiver.is_none(), egui::Button::new(tr(en,"打开 PCAP","Open PCAP"))).clicked() { if let Some(path) = choose_pcap() { self.open_capture(path); } }
                ui.separator(); ui.label(tr(en,"时长（秒，0 不限）","Seconds (0 = unlimited)"));
                ui.add_enabled(self.receiver.is_none(), egui::TextEdit::singleline(&mut self.duration).desired_width(55.0));
                ui.label(tr(en,"手机 IPv4","Device IPv4"));
                ui.add_enabled(self.receiver.is_none(), egui::TextEdit::singleline(&mut self.ip).desired_width(115.0).hint_text(tr(en,"全部设备","All devices")));
                if ui.button(tr(en,"打开保存目录","Open folder")).clicked() {
                    if let Err(e) = fs::create_dir_all(&self.folder).and_then(|_| Command::new("explorer.exe").arg(&self.folder).spawn().map(|_| ())) { self.state = format!("打开目录失败: {e}"); }
                }
                if ui.button(tr(en,"运行日志","Log")).clicked() { self.show_log = true; }
                if ui.button(tr(en,"字节对比","Compare")).clicked() { self.show_compare = true; }
                if ui.button(tr(en,"设置","Settings")).clicked() { self.show_settings = true; }
            });
            ui.horizontal(|ui| {
                let state = if en { self.state.replace("准备就绪", "Ready").replace("正在打开 PCAP…", "Opening PCAP…").replace("PCAP 已打开", "PCAP opened").replace("打开 PCAP 失败", "Could not open PCAP").replace("正在抓取热点转发流量…", "Capturing forwarded hotspot traffic…").replace("正在停止并保存…", "Stopping and saving…").replace("抓包完成", "Capture complete").replace("抓包失败", "Capture failed").replace("启动失败", "Start failed").replace("停止失败", "Stop failed").replace("无法创建输出目录", "Cannot create output folder").replace("打开目录失败", "Cannot open folder").replace("时长请输入 0 到 86400 秒", "Duration must be 0–86400 seconds").replace("请输入有效的 IPv4 地址", "Enter a valid IPv4 address") } else { self.state.clone() };
                ui.label(RichText::new(state).color(if self.receiver.is_some() { if dark { Color32::from_rgb(70, 190, 125) } else { Color32::from_rgb(20, 120, 65) } } else { ui.visuals().text_color() }).strong());
                if let Some(file) = &self.last_file { ui.separator(); ui.label(format!("{} {}", if self.imported { tr(en,"已打开：","Opened:") } else { tr(en,"保存到：","Saved to:") }, file.display())); }
            });
            ui.add_space(3.0);
        });
        egui::TopBottomPanel::bottom("status").show(ctx, |ui| {
            ui.horizontal_wrapped(|ui| {
                ui.label(format!("{} {}  ·  {} {}  ·  {} {}", if self.imported { tr(en,"文件记录","File records") } else { tr(en,"已捕获","Captured") }, self.packet_count, tr(en,"窗口保留","In view"), self.packets.len(), tr(en,"跳过非 IPv4","Non-IPv4 skipped"), self.skipped));
                ui.separator(); ui.label(tr(en,"完整数据保存在 PCAP  ·  域名不能确定 App  ·  HTTPS 通常加密","Full capture saved to PCAP · Domains do not identify apps · HTTPS is usually encrypted"));
            });
        });
        egui::SidePanel::left("packets").resizable(true).default_width(340.0).min_width(260.0).show(ctx, |ui| {
            ui.add_space(5.0);
            ui.horizontal(|ui| { ui.heading(tr(en,"数据包列表","Packets")); ui.label(RichText::new(format!("{} / {}", self.packets.len(), self.packet_count)).color(muted)); });
            ui.horizontal(|ui| {
                ui.selectable_value(&mut self.show_flows, false, tr(en,"数据包","Packets"));
                ui.selectable_value(&mut self.show_flows, true, tr(en,"连接","Connections"));
            });
            ui.horizontal_wrapped(|ui| {
                egui::ComboBox::from_id_salt("category").selected_text(local_category(en, &self.filter)).show_ui(ui, |ui| {
                    for category in ["全部", "DNS", "HTTP（可能）", "TLS/HTTPS（可能）", "UDP 443（可能为 QUIC）", "TCP", "UDP", "ICMP", "其他"] {
                        ui.selectable_value(&mut self.filter, category.to_owned(), local_category(en, category));
                    }
                });
                ui.add(egui::TextEdit::singleline(&mut self.search).desired_width(160.0).hint_text(tr(en,"搜索 IP、端口、域名","Search IP, port, domain")));
                if ui.button(tr(en,"清除","Clear")).clicked() { self.search.clear(); self.filter = "全部".into(); }
            });
            if let Some(key) = &self.selected_flow {
                ui.label(RichText::new(format!("{} {key}", tr(en,"当前连接：","Connection:"))).color(muted));
                if ui.button(tr(en,"显示所有连接","Show all connections")).clicked() { self.selected_flow = None; }
            }
            ui.small(tr(en,"连接统计仅基于窗口保留且符合筛选的数据包；NAT 可能拆分连接。","Connection totals cover retained, matching packets only; NAT may split a connection."));
            ui.separator();
            egui::ScrollArea::vertical().id_salt("packet_list").auto_shrink([false, false]).show(ui, |ui| {
                let search = self.search.to_lowercase();
                let mut shown = 0;
                if self.show_flows {
                    let mut flows: HashMap<String, (usize, usize)> = HashMap::new();
                    for packet in &self.packets {
                        if !matches_filter(packet, &self.filter, &search) { continue; }
                        if let Some(key) = &packet.flow { let entry = flows.entry(key.clone()).or_insert((0,0)); entry.0 += 1; entry.1 += packet.hex.len() / 2; }
                    }
                    let mut items: Vec<_> = flows.into_iter().collect();
                    items.sort_by(|a,b| b.1.1.cmp(&a.1.1).then_with(|| a.0.cmp(&b.0)));
                    for (key, (count, bytes)) in items {
                        shown += 1;
                        let response = egui::Frame::new().fill(card).inner_margin(egui::Margin::same(9)).corner_radius(5).show(ui, |ui| {
                            ui.set_min_width((ui.available_width() - 20.0).max(180.0));
                            ui.label(RichText::new(format!("{count} {}  ·  {bytes} B", tr(en,"包","packets"))).strong());
                            ui.add(egui::Label::new(RichText::new(&key).size(12.5).color(muted)).truncate());
                        });
                        if response.response.interact(egui::Sense::click()).on_hover_text(&key).clicked() {
                            self.selected_flow = Some(key.clone()); self.show_flows = false;
                            self.selected = self.packets.iter().find(|p| p.flow.as_ref() == Some(&key) && matches_filter(p, &self.filter, &search)).map(|p| p.id);
                        }
                        ui.add_space(2.0);
                    }
                } else { for packet in &self.packets {
                    if !matches_filter(packet, &self.filter, &search) { continue; }
                    if self.selected_flow.as_ref().map_or(false, |key| packet.flow.as_ref() != Some(key)) { continue; }
                    shown += 1;
                    let selected = self.selected == Some(packet.id);
                    let bg = if selected { selected_card } else { card };
                    let item = egui::Frame::new().fill(bg).inner_margin(egui::Margin::same(9)).corner_radius(5).show(ui, |ui| {
                        ui.set_min_width((ui.available_width() - 20.0).max(180.0));
                        ui.horizontal(|ui| {
                            ui.label(RichText::new(format!("#{:05}", packet.id)).monospace().color(muted));
                            ui.label(RichText::new(local_category(en, packet.category)).strong().color(if dark { category_color(packet.category) } else { category_color(packet.category).gamma_multiply(0.55) }));
                            ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| { ui.label(RichText::new(format!("{} B", packet.hex.len() / 2)).small().color(muted)); });
                        });
                        ui.add(egui::Label::new(RichText::new(if en { translate_detail(&packet.detail) } else { packet.detail.clone() }).size(12.5).color(if dark { Color32::from_rgb(190, 203, 218) } else { Color32::from_rgb(45, 63, 81) })).truncate());
                    });
                    if item.response.interact(egui::Sense::click()).on_hover_text(&packet.summary).clicked() { self.selected = Some(packet.id); }
                    ui.add_space(2.0);
                }}
                if shown == 0 { ui.label(tr(en,"没有匹配的数据包","No matching packets")); }
            });
        });
        egui::CentralPanel::default().show(ctx, |ui| {
            if let Some(packet) = self.packets.iter().find(|p| Some(p.id) == self.selected) {
                ui.add_space(5.0);
                ui.horizontal(|ui| {
                    ui.heading(format!("{} #{:05}", tr(en,"数据包","Packet"), packet.id));
                    ui.label(RichText::new(local_category(en, packet.category)).strong().color(if dark { category_color(packet.category) } else { category_color(packet.category).gamma_multiply(0.55) }));
                });
                ui.label(RichText::new(if en { translate_detail(&packet.detail) } else { packet.detail.clone() }).color(muted));
                ui.add_space(5.0);
                egui::Frame::new().fill(card).inner_margin(egui::Margin::same(12)).corner_radius(6).show(ui, |ui| {
                    ui.set_min_width(ui.available_width());
                    egui::CollapsingHeader::new(RichText::new(tr(en,"协议详情","Protocol details")).strong()).default_open(true).show(ui, |ui| {
                        egui::ScrollArea::vertical().id_salt("details").max_height(120.0).show(ui, |ui| {
                            let columns = if ui.available_width() < 590.0 { 2 } else { 4 };
                            egui::Grid::new("detail_grid").num_columns(columns).spacing([18.0, 4.0]).show(ui, |ui| {
                                let info = if en { translate_detail(&packet.info) } else { packet.info.clone() };
                                for (index, line) in info.lines().enumerate() {
                                    if let Some((key, value)) = line.split_once('：') {
                                        ui.label(RichText::new(key).color(muted));
                                        ui.label(value);
                                    } else { ui.label(""); ui.label(line); }
                                    if columns == 2 || index % 2 == 1 { ui.end_row(); }
                                }
                            });
                        });
                    });
                });
                ui.add_space(10.0);
                let bytes = decode_hex(&packet.hex);
                let payload_offset = metadata::payload_offset(&bytes);
                let view_offset = if self.payload_only { payload_offset.unwrap_or(bytes.len()) } else { 0 };
                let view_bytes = &bytes[view_offset..];
                ui.horizontal_wrapped(|ui| {
                    ui.heading(tr(en,"数据内容","Packet data")); ui.label(RichText::new(format!("{} {}", view_bytes.len(), tr(en,"字节","bytes"))).color(muted));
                        if ui.button(tr(en,"设为 A","Set as A")).clicked() { self.compare_a = Some((packet.id, bytes.clone())); self.show_compare = true; }
                        if ui.button(tr(en,"设为 B","Set as B")).clicked() { self.compare_b = Some((packet.id, bytes.clone())); self.show_compare = true; }
                        if ui.button(tr(en,"复制十六进制","Copy hex bytes")).clicked() { ctx.copy_text(view_bytes.iter().map(|b| format!("{b:02X}")).collect::<Vec<_>>().join(" ")); }
                        if ui.button(tr(en,"复制当前视图","Copy view")).clicked() { ctx.copy_text(if self.text_view { render_text(view_bytes) } else { render_hex_at(view_bytes, view_offset) }); }
                });
                ui.horizontal(|ui| {
                    ui.selectable_value(&mut self.text_view, false, tr(en,"十六进制 / ASCII","Hex / ASCII"));
                    ui.selectable_value(&mut self.text_view, true, tr(en,"UTF-8 文本","UTF-8 text"));
                    ui.separator();
                    ui.checkbox(&mut self.payload_only, tr(en,"只显示载荷","Payload only"));
                });
                if self.payload_only && payload_offset.is_none() { ui.small(tr(en,"该包没有可识别的 TCP/UDP 载荷。","This packet has no recognizable TCP/UDP payload.")); }
                else if self.text_view { ui.small(tr(en,"UTF-8 解码；不可解码或控制字符显示为 ·，加密数据不可直接阅读。","UTF-8 decoding; invalid/control characters appear as ·. Encrypted data is not readable.")); }
                else { ui.small(tr(en,"每行 16 字节：偏移量 | 十六进制字节 | ASCII（不可打印字符显示为 .）","16 bytes per row: offset | hexadecimal bytes | ASCII (non-printable bytes are .)")); }
                ui.separator();
                let content = if self.text_view { render_text(view_bytes) } else { render_hex_at(view_bytes, view_offset) };
                egui::ScrollArea::both().id_salt("packet_content").auto_shrink([false, false]).show(ui, |ui| {
                    egui::Frame::new().fill(if dark { Color32::from_rgb(10, 16, 24) } else { Color32::WHITE }).inner_margin(egui::Margin::same(14)).corner_radius(5).show(ui, |ui| {
                        ui.set_min_width(ui.available_width());
                        ui.add(egui::Label::new(RichText::new(content).monospace().size(self.settings.font_size).color(if dark { Color32::from_rgb(199, 218, 230) } else { Color32::from_rgb(35, 53, 69) })).selectable(true).wrap_mode(egui::TextWrapMode::Extend));
                    });
                });
            } else {
                ui.add_space(60.0);
                ui.vertical_centered(|ui| {
                    ui.label(RichText::new("◈").size(40.0).color(Color32::from_rgb(76, 157, 172)));
                    ui.heading(tr(en,"选择一个数据包","Select a packet"));
                    ui.label(RichText::new(tr(en,"开始抓包后，在左侧选择数据包查看协议与内容","Start capturing and select a packet to view its protocol and contents")).color(muted));
                });
            }
        });
        egui::Window::new(tr(en,"运行日志","Capture log")).open(&mut self.show_log).default_size([700.0, 400.0]).show(ctx, |ui| {
            egui::ScrollArea::both().stick_to_bottom(true).show(ui, |ui| { ui.label(RichText::new(&self.log).monospace()); });
        });
        egui::Window::new(tr(en,"原始数据包字节对比","Raw packet byte comparison")).open(&mut self.show_compare).default_size([720.0, 560.0]).show(ctx, |ui| {
            ui.label(tr(en,"在数据包详情中选择“设为 A”和“设为 B”。对比包含 IP 和传输头，不会重组 TCP 流。","Choose Set as A and Set as B in packet details. Comparison includes IP/transport headers and does not reassemble TCP streams."));
            ui.horizontal(|ui| {
                ui.label(format!("A: {}", self.compare_a.as_ref().map(|(id,b)| format!("#{id} / {} bytes", b.len())).unwrap_or_else(|| "—".into())));
                ui.separator(); ui.label(format!("B: {}", self.compare_b.as_ref().map(|(id,b)| format!("#{id} / {} bytes", b.len())).unwrap_or_else(|| "—".into())));
            });
            if let (Some((_,a)), Some((_,b))) = (&self.compare_a, &self.compare_b) {
                let common = a.len().min(b.len());
                let differences: Vec<usize> = (0..common).filter(|&i| a[i] != b[i]).collect();
                let first = differences.first().copied().or_else(|| if a.len() != b.len() { Some(common) } else { None });
                ui.separator();
                ui.label(if a == b { tr(en,"两个数据包完全一致","Packets are identical").to_owned() } else { format!("{}: {}  ·  {}: {}  ·  {}: {}", tr(en,"首个差异偏移","First difference"), first.map(|n| format!("0x{n:X}")).unwrap_or_else(|| "—".into()), tr(en,"重叠部分不同字节","Different bytes in overlap"), differences.len(), tr(en,"多出的字节","Unmatched tail bytes"), a.len().abs_diff(b.len())) });
                ui.small(tr(en,"显示前 200 个差异；偏移为十六进制。— 表示该包在此位置没有字节。","First 200 differences; offsets are hexadecimal. — means no byte at that offset."));
                egui::ScrollArea::vertical().max_height(350.0).show(ui, |ui| {
                    let mut shown = 0;
                    for i in 0..a.len().max(b.len()) {
                        if a.get(i) != b.get(i) {
                            ui.monospace(format!("0x{i:08X}   A: {}    B: {}", a.get(i).map(|x| format!("{x:02X}")).unwrap_or_else(|| "—".into()), b.get(i).map(|x| format!("{x:02X}")).unwrap_or_else(|| "—".into())));
                            shown += 1; if shown >= 200 { break; }
                        }
                    }
                });
            } else { ui.add_space(12.0); ui.label(tr(en,"请先选择两个数据包。","Select two packets first.")); }
        });
        let previous = self.settings.clone();
        egui::Window::new(tr(en,"设置","Settings")).open(&mut self.show_settings).default_width(620.0).min_width(540.0).resizable(true).show(ctx, |ui| {
            ui.add_space(2.0);
            ui.label(RichText::new(tr(en,"个性化","Personalization")).size(22.0).strong());
            ui.label(RichText::new(tr(en,"调整窗口外观和数据查看方式","Make the workspace comfortable for you")).color(muted));
            ui.add_space(10.0);
            egui::ScrollArea::vertical().max_height(610.0).show(ui, |ui| {
                ui.label(RichText::new(tr(en,"外观和语言","Appearance & language")).strong());
                settings_card(ui, dark, tr(en,"应用主题","App theme"), tr(en,"选择浅色或深色外观","Choose a light or dark appearance"), |ui| {
                    egui::ComboBox::from_id_salt("theme_setting").selected_text(if self.settings.dark { tr(en,"深色","Dark") } else { tr(en,"浅色","Light") }).width(100.0).show_ui(ui, |ui| {
                        ui.selectable_value(&mut self.settings.dark, false, tr(en,"浅色","Light"));
                        ui.selectable_value(&mut self.settings.dark, true, tr(en,"深色","Dark"));
                    });
                });
                settings_card(ui, dark, tr(en,"显示语言","Display language"), tr(en,"更改窗口和菜单的语言","Change the language of menus and controls"), |ui| {
                    egui::ComboBox::from_id_salt("language_setting").selected_text(if self.settings.english { "English" } else { "简体中文" }).width(100.0).show_ui(ui, |ui| {
                        ui.selectable_value(&mut self.settings.english, false, "简体中文"); ui.selectable_value(&mut self.settings.english, true, "English");
                    });
                });
                settings_card(ui, dark, tr(en,"界面缩放","Interface scale"), tr(en,"调整整个窗口的显示大小","Adjust the size of the interface"), |ui| {
                    ui.add_sized([175.0, 30.0], egui::Slider::new(&mut self.settings.zoom, 0.8..=1.5).step_by(0.05).suffix("×"));
                });
                ui.add_space(10.0); ui.label(RichText::new(tr(en,"数据查看","Data viewer")).strong());
                settings_card(ui, dark, tr(en,"数据字号","Data font size"), tr(en,"调整十六进制和文本内容字号","Change the hex and text viewer font size"), |ui| {
                    ui.add_sized([175.0, 30.0], egui::Slider::new(&mut self.settings.font_size, 11.0..=20.0).step_by(1.0));
                });
                settings_card(ui, dark, tr(en,"列表保留包数","Packets kept in the list"), tr(en,"完整数据始终保存在 PCAP 文件中","Full capture data is always saved to PCAP"), |ui| {
                    egui::ComboBox::from_id_salt("limit").selected_text(self.settings.packet_limit.to_string()).width(100.0).show_ui(ui, |ui| { for n in [100, 500, 1000, 2000] { ui.selectable_value(&mut self.settings.packet_limit, n, n.to_string()); } });
                });
                ui.add_space(12.0);
                ui.horizontal(|ui| {
                    ui.label(RichText::new(tr(en,"更改会自动保存 · 列表内存上限为 16 MiB","Changes save automatically · List memory limit: 16 MiB")).size(12.0).color(muted));
                    ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| { if ui.button(tr(en,"恢复默认设置","Restore defaults")).clicked() { self.settings = Settings::default(); } });
                });
            });
        });
        if self.settings != previous {
            apply_theme(ctx, self.settings.dark); ctx.set_zoom_factor(self.settings.zoom);
            while self.packets.len() > self.settings.packet_limit {
                if let Some(old) = self.packets.pop_front() { self.packet_bytes -= old.hex.len(); if self.selected == Some(old.id) { self.selected = self.packets.front().map(|p| p.id); } }
            }
            if let Err(e) = self.settings.save(&self.root.join("settings.ini")) { self.state = format!("{}: {e}", tr(self.settings.english,"保存设置失败","Could not save settings")); }
        }
    }
}

#[cfg(test)]
mod view_tests {
    use super::*;
    #[test]
    fn displays_hex_offsets_and_ascii() {
        let view = render_hex(b"Hello\x00world!");
        assert!(view.contains("48 65 6C 6C 6F 00"));
        assert!(view.contains("Hello.world!"));
        assert!(view.contains("00000000"));
    }
    #[test]
    fn utf8_view_preserves_chinese_and_masks_binary() {
        assert_eq!(render_text("你好".as_bytes()), "你好");
        assert_eq!(render_text(&[0xff, 0, b'A']), "··A");
    }
    #[test]
    fn transport_filter_includes_specialized_categories() {
        let packet = Packet { id: 1, summary: "HTTPS test".into(), hex: String::new(), detail: String::new(), category: "TLS/HTTPS（可能）", info: String::new(), protocol: 6, flow: None };
        assert!(matches_filter(&packet, "TCP", "https"));
        assert!(!matches_filter(&packet, "UDP", ""));
        assert!(matches_filter(&packet, "TLS/HTTPS（可能）", ""));
    }
    #[test]
    fn payload_hex_keeps_original_offset() {
        assert!(render_hex_at(b"AB", 28).contains("0000001C    41 42"));
    }
}
