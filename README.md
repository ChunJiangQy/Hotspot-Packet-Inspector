# Hotspot Packet Inspector

Windows hotspot packet capture and inspection with a Rust desktop interface, raw packet comparison, and a local MCP server.

**中文：**Windows 热点抓包和分析工具，提供 Rust 图形界面、数据包字节对比与本地 MCP 接口。[中文说明](#中文说明)。

## Features

- Capture forwarded IPv4 traffic from devices connected to a Windows mobile hotspot; capture local traffic through the command-line tool.
- Browse packets by protocol, search IP addresses, ports and visible domains, and inspect packet details.
- Open classic PCAP files and browse retained packets grouped by connection.
- View raw bytes as hex and ASCII or decode them as UTF-8; inspect TCP/UDP payloads separately.
- Search packet contents or a reassembled TCP direction using exact UTF-8 or hexadecimal byte patterns.
- Reassemble retained TCP packets by sequence number in each direction, with missing bytes and overlapping retransmissions identified.
- Compare two raw IP packets byte by byte, including headers, and save captures as PCAP files.
- Switch between light and dark themes, Chinese and English, and adjust scaling and data font size.
- Connect MCP clients to read capture status, list captures, inspect packets, and compare packet bytes.

The desktop interface is written in Rust with egui. The C# backend captures packets using [WinDivert](https://reqrypt.org/windivert.html).

## Requirements

- Windows x64 with .NET Framework 4 or later.
- Administrator approval to start the graphical capture application and load the WinDivert driver.
- A Windows mobile hotspot and a connected client for hotspot capture.
- Keep the backend executable, `WinDivert.dll`, and `WinDivert64.sys` together under `windivert/WinDivert-2.2.2-A/x64/`.

The repository includes the current Windows executables and required WinDivert binaries. Keep the directory structure intact when moving the application.

## Quick start

1. Enable **Mobile hotspot** in Windows and connect the phone.
2. Open `PacketTool.exe` and approve the administrator prompt.
3. Click **Start capture**. Set a duration in seconds, or enter `0` for an unlimited capture. Optionally enter the phone's IPv4 address.
4. Select a packet to inspect its details and bytes. Use **Set as A** and **Set as B** to compare two packets.
5. Click **Stop & save**, or wait for the duration to expire. PCAP files are saved under `captures/`.

The **Settings** window controls language, theme, scaling, font size, and the number of packets retained in the interface. The on-screen list also has a 16 MiB limit; captured packets beyond that list remain in the PCAP file.

Use **Open PCAP** to revisit a classic PCAP file. Raw IPv4 and Ethernet link types are supported; Ethernet headers are removed for inspection and non-IPv4 records are skipped. PCAPNG is not supported. For large files, the view retains only the newest packets within the configured packet and memory limits. The **Connections** tab groups retained packets by IP addresses, ports, and transport protocol. Its packet and byte totals cover only retained packets matching the current filters; NAT can split one conversation into multiple entries. Selecting a connection filters the packet list.

Select a TCP packet and choose **View TCP stream** to inspect a snapshot of retained packets sharing its address/port tuple. Choose a direction, search its bytes, and click a match to jump to its page. Gaps are shown as `??`; conflicting overlaps retain the first captured byte. The view does not reassemble IP fragments or distinguish separate connections that reuse a tuple. The beginning and end may be incomplete, and each direction's sequence span is limited to 8 MiB. A snapshot does not update until refreshed. Search results are limited to 200 matches and cannot cross missing data. This is packet-level observation, not decryption.

To search an individual packet, select its whole-packet or payload-only view and choose **Find bytes**. UTF-8 text and hexadecimal patterns are exact, case-sensitive byte searches. Clicking a result jumps to its offset in the full packet's hex view.

### Command line

Run PowerShell as administrator from the project directory:

```powershell
# Capture forwarded hotspot traffic for 60 seconds
.\run.ps1 capture phone.pcap --hotspot --duration 60 --stats 5

# Capture local traffic associated with a process
.\run.ps1 capture local.pcap --pname chrome --duration 60

# Compare two PCAP files using the backend's flow comparison
.\run.ps1 compare A.pcap B.pcap --report diff.txt --detail
```

`--ip` filters an IPv4 address and `--port` filters TCP/UDP ports. `--hotspot` cannot be combined with `--pid` or `--pname`: forwarded phone traffic does not belong to a local Windows process. `--full` ignores the automatically constructed IP and port filters.

The GUI and MCP compare individual raw IP packets, including headers. The backend `compare` command instead compares flow data; differing connection tuples may appear as separate flows. The payload-only view shows one packet's TCP/UDP payload and does not reassemble a stream.

## MCP integration

The same executable provides a read-only MCP server using stdio. It does not listen on a network port or start or stop captures. Configure an MCP client to launch it with `--mcp`. For clients using the `mcpServers` format:

```json
{
  "mcpServers": {
    "hotspot-packet-inspector": {
      "command": "C:\\path\\to\\Hotspot-Packet-Inspector\\PacketTool.exe",
      "args": ["--mcp"]
    }
  }
}
```

| Tool | Purpose |
| --- | --- |
| `capture_status` | Read the last status reported by the GUI. |
| `list_captures` | List PCAP files in the application's `captures` directory. |
| `read_packets` | Read raw IP packets from a capture; packet indexes start at zero. |
| `compare_packets` | Compare two raw IP packets by byte. |

The file argument accepts only a PCAP filename inside `captures/`. An active capture is flushed approximately once per second when traffic is present. The GUI status is the last saved state and can be stale after an unexpected exit. Client configuration formats and locations vary.

## Build from source

The Rust GUI requires a Rust toolchain for `x86_64-pc-windows-msvc`. The C# backend can be built with the .NET Framework compiler included in Windows. From the project root:

```powershell
# Rebuild the backend beside the WinDivert binaries
$csc = "$env:WINDIR\Microsoft.NET\Framework64\v4.0.30319\csc.exe"
& $csc /nologo /platform:x64 /target:exe /optimize+ `
  /out:windivert\WinDivert-2.2.2-A\x64\PacketTool.exe PacketTool.cs

# Rebuild the desktop and MCP executable
Push-Location gui
cargo build --release
cargo test --release
Pop-Location
Copy-Item gui\target\release\packet-tool-gui.exe PacketTool.exe -Force
```

Close the application before replacing its executable. The GUI and backend communicate through a local child process; the GUI requests administrator approval before capture.

## Scope and limitations

- Hotspot mode captures **forwarded IPv4 packets**, not Wi-Fi link-layer frames or IPv6. Phone-to-PC traffic is outside this mode.
- Other hotspot clients' traffic may also appear. NAT can change addresses and produce records on both sides of a translation; IP filtering may miss some packets.
- Hotspot capture alone cannot reliably identify which Android app generated a packet. A domain, address, or inferred protocol is only a clue and may be shared by many apps.
- Visible domains come from observed DNS, HTTP Host headers, or TLS SNI when available. Encryption, encrypted DNS, fragmentation, or other protocols can prevent identification.
- HTTPS and other encrypted payloads remain encrypted. UTF-8 decoding does not decrypt them.
- Capture files can contain sensitive information; inspect only traffic and devices you are authorized to access.

## Project layout

```text
PacketTool.exe                       GUI and MCP entry point
PacketTool.cs                        C# capture and comparison backend
run.ps1                              PowerShell command-line wrapper
gui/                                 Rust GUI and MCP source
windivert/WinDivert-2.2.2-A/        WinDivert license and runtime files
captures/                            Generated PCAPs (not tracked)
```

WinDivert is distributed under its own license; see [`windivert/WinDivert-2.2.2-A/LICENSE`](windivert/WinDivert-2.2.2-A/LICENSE). No license for project-authored code is specified in this repository.

## Acknowledgements

Thanks to the [WinDivert project and its maintainers](https://github.com/basil00/WinDivert) for the packet capture driver, and to [Dragonreversal](https://github.com/Dragonreversal) for their contributions and inspiration.

感谢 WinDivert 项目及其维护者提供抓包驱动，也感谢 [Dragonreversal](https://github.com/Dragonreversal) 的贡献与启发。

## 中文说明

Hotspot Packet Inspector 捕获通过 Windows 移动热点转发的 IPv4 数据包，支持协议分类、地址和域名搜索、十六进制/ASCII 与 UTF-8 查看、单包字节对比和 PCAP 保存。

**使用方法：**开启电脑移动热点并连接手机，运行 `PacketTool.exe`，允许管理员权限后点击“开始抓包”。选择数据包可查看内容；分别点击“设为 A”“设为 B”进行对比。抓包文件保存在 `captures/`；“设置”中可切换主题、语言、缩放和字号。

选择 TCP 数据包后点击“查看 TCP 流”，可按方向重组当前保留的同一地址和端口组合的数据，并以 UTF-8 文本或十六进制搜索。缺失字节显示为 `??`，重传冲突保留先捕获的字节；不重组 IP 分片，也不区分复用同一地址和端口的不同连接。流可能缺少开头或结尾，单方向跨度上限为 8 MiB，抓包期间须手动刷新快照。单包可通过“搜索内容”查找。搜索是区分大小写的精确字节匹配，最多显示 200 个结果，不会跨越缺失片段，也不会解密 HTTPS。

点击“打开 PCAP”可以回看传统 PCAP 格式的 IPv4 原始包或以太网包（暂不支持 PCAPNG，会跳过非 IPv4 记录）。大文件只保留符合内存和数量限制的最新数据包。“连接”页按地址、端口和协议汇总当前窗口中符合筛选条件的包，点击连接可筛选其数据包；NAT 可能将同一通信拆成多个条目。

**MCP：**同一个程序使用 `--mcp` 参数，以 stdio 提供抓包状态、文件列表、数据包读取和单包对比。配置示例见上方 [MCP integration](#mcp-integration)。

**注意：**热点抓包不能可靠识别手机上是哪个 App 产生了数据；域名和端口只能辅助判断。HTTPS 内容通常仍然加密，IPv6 和 Wi-Fi 链路层数据不在热点模式的默认范围内。单包载荷查看和对比不会重组 TCP 流。
