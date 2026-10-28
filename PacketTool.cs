

using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Net;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading;

namespace PacketTool
{
    // ====== WinDivert P/Invoke ======
    internal static class WinDivert
    {
        public const int LAYER_NETWORK = 0;
        public const int LAYER_NETWORK_FORWARD = 1;
        public const ulong FLAG_SNIFF = 1;
        public const ulong FLAG_RECV_ONLY = 4;

        [StructLayout(LayoutKind.Sequential, Pack = 1)]
        public struct WINDIVERT_ADDRESS
        {
            public long Timestamp;
            public uint LayerFlags;
            public uint Reserved;
            public uint IfIdx;
            public uint SubIfIdx;
        }

        [DllImport("WinDivert.dll", CallingConvention = CallingConvention.StdCall, CharSet = CharSet.Ansi, SetLastError = true)]
        public static extern IntPtr WinDivertOpen(string filter, int layer, short priority, ulong flags);

        [DllImport("WinDivert.dll", CallingConvention = CallingConvention.StdCall, SetLastError = true)]
        public static extern bool WinDivertRecv(IntPtr handle, byte[] pPacket, uint packetLen, out uint pRecvLen, out WINDIVERT_ADDRESS pAddr);

        [DllImport("WinDivert.dll", CallingConvention = CallingConvention.StdCall)]
        public static extern bool WinDivertClose(IntPtr handle);

        [DllImport("WinDivert.dll", CallingConvention = CallingConvention.StdCall, SetLastError = true)]
        public static extern bool WinDivertShutdown(IntPtr handle, int how);

        [DllImport("WinDivert.dll", CallingConvention = CallingConvention.StdCall)]
        public static extern bool WinDivertSetParam(IntPtr handle, int param, ulong value);
    }

    // ====== pcap file (LINKTYPE_RAW=101, IP packets) ======
    internal class PcapWriter : IDisposable
    {
        private readonly BinaryWriter _w;
        public PcapWriter(string path)
        {
            _w = new BinaryWriter(new FileStream(path, FileMode.Create, FileAccess.Write, FileShare.Read));
            _w.Write(0xa1b2c3d4u);
            _w.Write((ushort)2);
            _w.Write((ushort)4);
            _w.Write(0);
            _w.Write(0);
            _w.Write(65535u);
            _w.Write(101u);
        }

        public void WritePacket(byte[] data, int len, long tsMicros)
        {
            uint sec = (uint)(tsMicros / 1000000L);
            uint usec = (uint)(tsMicros % 1000000L);
            _w.Write(sec);
            _w.Write(usec);
            _w.Write((uint)len);
            _w.Write((uint)len);
            _w.Write(data, 0, len);
        }

        public void Dispose() { if (_w != null) _w.Dispose(); }
        public void Flush() { _w.Flush(); }
    }

    internal class PcapReader : IDisposable
    {
        private readonly BinaryReader _r;
        public PcapReader(string path)
        {
            _r = new BinaryReader(File.OpenRead(path));
            uint magic = _r.ReadUInt32();
            if (magic != 0xa1b2c3d4u && magic != 0xd4c3b2a1u)
                throw new Exception("Not a pcap file (bad magic)");
            _r.ReadUInt16();
            _r.ReadUInt16();
            _r.ReadInt32();
            _r.ReadUInt32();
            _r.ReadUInt32();
            _r.ReadUInt32();
        }

        public byte[] ReadPacket(out long tsMicros)
        {
            tsMicros = 0;
            try
            {
                uint sec = _r.ReadUInt32();
                uint usec = _r.ReadUInt32();
                uint incl = _r.ReadUInt32();
                _r.ReadUInt32();
                tsMicros = sec * 1000000L + usec;
                return _r.ReadBytes((int)incl);
            }
            catch (EndOfStreamException) { return null; }
        }

        public void Dispose() { if (_r != null) _r.Dispose(); }
    }

    // ====== IP/TCP/UDP parsing ======
    internal class IpPacket
    {
        public uint SrcIp;
        public uint DstIp;
        public byte Protocol;
        public byte[] Payload;
        public int HeaderLen;

        public static IpPacket Parse(byte[] data, int len)
        {
            if (len < 20) return null;
            byte vh = data[0];
            int version = (vh >> 4) & 0xF;
            if (version != 4) return null;
            int ihl = (vh & 0xF) * 4;
            if (ihl < 20 || ihl > len) return null;
            byte proto = data[9];
            uint src = (uint)((data[12] << 24) | (data[13] << 16) | (data[14] << 8) | data[15]);
            uint dst = (uint)((data[16] << 24) | (data[17] << 16) | (data[18] << 8) | data[19]);
            int totalLen = (data[2] << 8) | data[3];
            if (totalLen < ihl || totalLen > len) totalLen = len;
            byte[] payload = new byte[totalLen - ihl];
            Array.Copy(data, ihl, payload, 0, payload.Length);
            return new IpPacket { SrcIp = src, DstIp = dst, Protocol = proto, Payload = payload, HeaderLen = ihl };
        }

        public static string IpToStr(uint ip)
        {
            return string.Format("{0}.{1}.{2}.{3}",
                (ip >> 24) & 0xFF, (ip >> 16) & 0xFF, (ip >> 8) & 0xFF, ip & 0xFF);
        }
    }

    // Generic segment (TCP or UDP)
    internal class Segment
    {
        public uint SrcIp, DstIp;
        public ushort SrcPort, DstPort;
        public uint Seq;
        public byte Flags;
        public byte Protocol; // 6=TCP, 17=UDP
        public byte[] Payload;
        public long TsMicros;
        public const byte TCP_SYN = 0x02;
        public const byte TCP_SYN_ACK = 0x12;

        // Flow key: symmetric (same for both directions)
        public string FlowKey
        {
            get
            {
                uint a = SrcIp, b = DstIp;
                ushort pa = SrcPort, pb = DstPort;
                if (a > b) { Swap(ref a, ref b); Swap(ref pa, ref pb); }
                else if (a == b && pa > pb) { Swap(ref pa, ref pb); }
                return string.Format("{0}:{1}-{2}:{3}", IpPacket.IpToStr(a), pa, IpPacket.IpToStr(b), pb);
            }
        }

        // Direction key: asymmetric (one per direction)
        public string DirKey
        {
            get { return string.Format("{0}:{1}->{2}:{3}", IpPacket.IpToStr(SrcIp), SrcPort, IpPacket.IpToStr(DstIp), DstPort); }
        }

        static void Swap<T>(ref T a, ref T b) { T t = a; a = b; b = t; }
    }

    // ====== Main program ======
    internal class Program
    {
        static volatile bool g_running = true;

        static int Main(string[] args)
        {
            if (args.Length < 1)
            {
                PrintUsage();
                return 1;
            }
            string cmd = args[0].ToLowerInvariant();
            if (cmd == "capture") return RunCapture(args);
            if (cmd == "compare") return RunCompare(args);
            if (cmd == "dumpflow") return RunDumpFlow(args);
            if (cmd == "listpid") return ListPidConnections(args);
            if (cmd == "listproc") return ListProcByName(args);
            PrintUsage();
            return 1;
        }

        static void PrintUsage()
        {
            Console.WriteLine("PacketTool v2.0 - Generic WinDivert capture + byte comparison");
            Console.WriteLine("Usage:");
            Console.WriteLine("  PacketTool.exe capture  <out.pcap> [--pid <pid>] [--pname <name>]");
            Console.WriteLine("                          [--port <p1,p2>] [--ip <addr>] [--duration <sec>]");
            Console.WriteLine("                          [--filter \"<expr>\"] [--full] [--stats <sec>]");
            Console.WriteLine("  PacketTool.exe compare  <f1.pcap> <f2.pcap> [--report <out.txt>]");
            Console.WriteLine("                          [--port <p>] [--detail] [--flow <key>] [--bin <prefix>]");
            Console.WriteLine("  PacketTool.exe dumpflow <pcap> <ip> <port> [--out <base>]");
            Console.WriteLine("  PacketTool.exe listpid  <pid|pname>");
            Console.WriteLine("  PacketTool.exe listproc <pname>");
            Console.WriteLine("");
            Console.WriteLine("Notes:");
            Console.WriteLine("  --pname supports '*' wildcard (e.g. --pname dnplayer*)");
            Console.WriteLine("  --pname aggregates ALL matching processes' connections");
            Console.WriteLine("  --duration 0 = unlimited (default, Ctrl+C to stop)");
            Console.WriteLine("  --stats N prints per-flow summary every N seconds");
            Console.WriteLine("  --full captures ALL IP traffic (no process/port filter)");
            Console.WriteLine("  --hotspot captures forwarded IPv4 traffic (e.g. mobile hotspot)");
        }

        // ============ Process lookup helpers ============
        static List<int> FindPidsByName(string namePattern)
        {
            var result = new List<int>();
            if (string.IsNullOrEmpty(namePattern)) return result;
            // Convert glob to regex
            string regex = "^" + System.Text.RegularExpressions.Regex.Escape(namePattern).Replace("\\*", ".*") + "$";
            var rx = new System.Text.RegularExpressions.Regex(regex, System.Text.RegularExpressions.RegexOptions.IgnoreCase);
            foreach (var p in Process.GetProcesses())
            {
                try
                {
                    if (rx.IsMatch(p.ProcessName)) result.Add(p.Id);
                }
                catch { }
            }
            return result;
        }

        static string GetProcessName(int pid)
        {
            try { return Process.GetProcessById(pid).ProcessName; }
            catch { return "?"; }
        }

        [DllImport("iphlpapi.dll", CallingConvention = CallingConvention.StdCall)]
        static extern uint GetExtendedTcpTable(IntPtr pTcpTable, ref uint pdwSize, bool bOrder, int ulAf, int tableClass, int reserved);

        [DllImport("iphlpapi.dll", CallingConvention = CallingConvention.StdCall)]
        static extern uint GetExtendedUdpTable(IntPtr pUdpTable, ref uint pdwSize, bool bOrder, int ulAf, int tableClass, int reserved);

        class TcpConn
        {
            public uint LocalAddr; public ushort LocalPort;
            public uint RemoteAddr; public ushort RemotePort;
            public int Pid; public int State;
        }

        static List<TcpConn> GetAllTcpConnections()
        {
            var result = new List<TcpConn>();
            uint size = 0;
            GetExtendedTcpTable(IntPtr.Zero, ref size, false, 2, 4 /*TCP_TABLE_OWNER_PID_ALL*/, 0);
            if (size == 0) return result;
            IntPtr buf = Marshal.AllocHGlobal((int)size);
            try
            {
                if (GetExtendedTcpTable(buf, ref size, false, 2, 4, 0) != 0) return result;
                int count = Marshal.ReadInt32(buf);
                long ptr = buf.ToInt64() + 4;
                int rowSize = 24; // MIB_TCPROW_OWNER_PID
                for (int i = 0; i < count; i++)
                {
                    int state = Marshal.ReadInt32((IntPtr)(ptr + i * rowSize + 0));
                    uint localAddr = (uint)Marshal.ReadInt32((IntPtr)(ptr + i * rowSize + 4));
                    uint localPort = (uint)Marshal.ReadInt32((IntPtr)(ptr + i * rowSize + 8));
                    uint remoteAddr = (uint)Marshal.ReadInt32((IntPtr)(ptr + i * rowSize + 12));
                    uint remotePort = (uint)Marshal.ReadInt32((IntPtr)(ptr + i * rowSize + 16));
                    int owningPid = Marshal.ReadInt32((IntPtr)(ptr + i * rowSize + 20));
                    result.Add(new TcpConn
                    {
                        State = state,
                        LocalAddr = ByteSwap(localAddr),
                        LocalPort = (ushort)((localPort >> 8) | ((localPort & 0xFF) << 8)),
                        RemoteAddr = ByteSwap(remoteAddr),
                        RemotePort = (ushort)((remotePort >> 8) | ((remotePort & 0xFF) << 8)),
                        Pid = owningPid
                    });
                }
            }
            finally { Marshal.FreeHGlobal(buf); }
            return result;
        }

        class UdpEndpoint
        {
            public uint LocalAddr; public ushort LocalPort; public int Pid;
        }

        static List<UdpEndpoint> GetAllUdpEndpoints()
        {
            var result = new List<UdpEndpoint>();
            uint size = 0;
            GetExtendedUdpTable(IntPtr.Zero, ref size, false, 2, 1 /*UDP_TABLE_OWNER_PID*/, 0);
            if (size == 0) return result;
            IntPtr buf = Marshal.AllocHGlobal((int)size);
            try
            {
                if (GetExtendedUdpTable(buf, ref size, false, 2, 1, 0) != 0) return result;
                int count = Marshal.ReadInt32(buf);
                long ptr = buf.ToInt64() + 4;
                int rowSize = 12; // MIB_UDPROW_OWNER_PID
                for (int i = 0; i < count; i++)
                {
                    uint localAddr = (uint)Marshal.ReadInt32((IntPtr)(ptr + i * rowSize + 0));
                    uint localPort = (uint)Marshal.ReadInt32((IntPtr)(ptr + i * rowSize + 4));
                    int owningPid = Marshal.ReadInt32((IntPtr)(ptr + i * rowSize + 8));
                    result.Add(new UdpEndpoint
                    {
                        LocalAddr = ByteSwap(localAddr),
                        LocalPort = (ushort)((localPort >> 8) | ((localPort & 0xFF) << 8)),
                        Pid = owningPid
                    });
                }
            }
            finally { Marshal.FreeHGlobal(buf); }
            return result;
        }

        static List<TcpConn> GetProcessTcpConnections(int pid)
        {
            return GetAllTcpConnections().FindAll(c => c.Pid == pid && c.State == 5 /*ESTABLISHED*/);
        }

        static List<UdpEndpoint> GetProcessUdpEndpoints(int pid)
        {
            return GetAllUdpEndpoints().FindAll(c => c.Pid == pid);
        }

        static uint ByteSwap(uint v)
        {
            return ((v & 0xFF) << 24) | ((v & 0xFF00) << 8) | ((v & 0xFF0000) >> 8) | ((v & 0xFF000000u) >> 24);
        }

        // ============ listpid: TCP+UDP for a PID or process name ============
        static int ListPidConnections(string[] args)
        {
            if (args.Length < 2)
            {
                Console.WriteLine("Usage: listpid <pid|pname>");
                return 1;
            }
            List<int> pids = new List<int>();
            string arg = args[1];
            int pidVal;
            if (int.TryParse(arg, out pidVal)) pids.Add(pidVal);
            else pids.AddRange(FindPidsByName(arg));

            if (pids.Count == 0)
            {
                Console.WriteLine("[!] No process matches: " + arg);
                return 2;
            }

            foreach (int pid in pids)
            {
                string pname = GetProcessName(pid);
                Console.WriteLine(string.Format("=== PID {0} ({1}) ===", pid, pname));
                var tcpConns = GetProcessTcpConnections(pid);
                Console.WriteLine(string.Format("TCP ({0}):", tcpConns.Count));
                foreach (var c in tcpConns)
                {
                    Console.WriteLine(string.Format("  {0}:{1} -> {2}:{3}  state={4}",
                        IpPacket.IpToStr(c.LocalAddr), c.LocalPort,
                        IpPacket.IpToStr(c.RemoteAddr), c.RemotePort, c.State));
                }
                var udpConns = GetProcessUdpEndpoints(pid);
                Console.WriteLine(string.Format("UDP ({0}):", udpConns.Count));
                foreach (var u in udpConns)
                {
                    Console.WriteLine(string.Format("  {0}:{1}  (local listener)",
                        IpPacket.IpToStr(u.LocalAddr), u.LocalPort));
                }
                Console.WriteLine();
            }
            return 0;
        }

        // ============ listproc: list all processes matching name ============
        static int ListProcByName(string[] args)
        {
            if (args.Length < 2)
            {
                Console.WriteLine("Usage: listproc <pname>");
                return 1;
            }
            var pids = FindPidsByName(args[1]);
            if (pids.Count == 0)
            {
                Console.WriteLine("[!] No process matches: " + args[1]);
                return 2;
            }
            var allTcp = GetAllTcpConnections();
            var allUdp = GetAllUdpEndpoints();
            Console.WriteLine(string.Format("=== {0} process(es) match '{1}' ===", pids.Count, args[1]));
            foreach (int pid in pids)
            {
                string pname = GetProcessName(pid);
                int tcount = allTcp.Count(c => c.Pid == pid);
                int ucount = allUdp.Count(c => c.Pid == pid);
                Console.WriteLine(string.Format("  PID {0,6}  {1,-25}  TCP={2}  UDP={3}", pid, pname, tcount, ucount));
            }
            return 0;
        }

        // ============ capture mode ============
        static int RunCapture(string[] args)
        {
            if (args.Length < 2)
            {
                Console.WriteLine("Usage: capture <out.pcap> [--hotspot] [--pid <pid>] [--pname <name>] [--port <p1,p2>] [--ip <addr>] [--duration <sec>] [--filter \"<expr>\"] [--full] [--stats <sec>]");
                return 1;
            }
            string outFile = args[1];
            List<int> pids = new List<int>();
            List<int> ports = new List<int>();
            string ipFilter = null;
            int duration = 0; // 0 = unlimited
            string userFilter = null;
            bool fullCapture = false;
            bool hotspot = false;
            bool processFilterRequested = false;
            string stopFile = null;
            bool hexOutput = false;
            int statsInterval = 0;

            for (int i = 2; i < args.Length; i++)
            {
                string a = args[i];
                if (a == "--pid" && i + 1 < args.Length)
                {
                    processFilterRequested = true;
                    foreach (var p in args[++i].Split(',')) pids.Add(int.Parse(p.Trim()));
                }
                else if (a == "--pname" && i + 1 < args.Length)
                {
                    processFilterRequested = true;
                    pids.AddRange(FindPidsByName(args[++i]));
                }
                else if (a == "--port" && i + 1 < args.Length)
                {
                    foreach (var p in args[++i].Split(',')) ports.Add(int.Parse(p.Trim()));
                }
                else if (a == "--ip" && i + 1 < args.Length) { ipFilter = args[++i]; }
                else if (a == "--duration" && i + 1 < args.Length) { duration = int.Parse(args[++i]); }
                else if (a == "--filter" && i + 1 < args.Length) { userFilter = args[++i]; }
                else if (a == "--full") { fullCapture = true; }
                else if (a == "--hotspot") { hotspot = true; }
                else if (a == "--stop-file" && i + 1 < args.Length) { stopFile = args[++i]; }
                else if (a == "--hex-output") { hexOutput = true; }
                else if (a == "--stats" && i + 1 < args.Length) { statsInterval = int.Parse(args[++i]); }
            }

            if (hotspot && processFilterRequested)
            {
                Console.WriteLine("[!] --hotspot cannot be combined with --pid or --pname; forwarded traffic has no local process.");
                return 1;
            }

            if (pids.Count > 0)
            {
                Console.WriteLine("[*] Target PIDs: " + string.Join(", ", pids));
                foreach (int pid in pids)
                {
                    Console.WriteLine(string.Format("    PID {0} = {1}", pid, GetProcessName(pid)));
                }
            }

            // Build filter
            string filter = userFilter;
            if (filter == null)
            {
                if (fullCapture)
                {
                    filter = "ip";
                }
                else
                {
                    var parts = new List<string>();
                    if (pids.Count > 0)
                    {
                        // Aggregate connections across all PIDs (sub-process aggregation)
                        var remoteIps = new HashSet<uint>();
                        var tcpPorts = new HashSet<ushort>(); // local TCP ports
                        var udpPorts = new HashSet<ushort>(); // local UDP ports
                        foreach (int pid in pids)
                        {
                            foreach (var c in GetProcessTcpConnections(pid))
                            {
                                remoteIps.Add(c.RemoteAddr);
                                tcpPorts.Add(c.LocalPort);
                            }
                            foreach (var u in GetProcessUdpEndpoints(pid))
                            {
                                udpPorts.Add(u.LocalPort);
                            }
                        }
                        var ipParts = new List<string>();
                        foreach (var ip in remoteIps)
                        {
                            string ipStr = IpPacket.IpToStr(ip);
                            ipParts.Add(string.Format("ip.SrcAddr == {0} or ip.DstAddr == {0}", ipStr));
                        }
                        foreach (var p in tcpPorts)
                        {
                            ipParts.Add(string.Format("tcp.SrcPort == {0} or tcp.DstPort == {0}", p));
                        }
                        foreach (var p in udpPorts)
                        {
                            ipParts.Add(string.Format("udp.SrcPort == {0} or udp.DstPort == {0}", p));
                        }
                        // Always include DNS (catch domain-based filtering)
                        ipParts.Add("udp.SrcPort == 53 or udp.DstPort == 53");
                        if (ipParts.Count > 0)
                        {
                            parts.Add("(" + string.Join(" or ", ipParts.ToArray()) + ")");
                        }
                    }
                    if (ports.Count > 0)
                    {
                        var ps = new List<string>();
                        foreach (var p in ports)
                        {
                            ps.Add(string.Format("tcp.DstPort == {0} or tcp.SrcPort == {0} or udp.DstPort == {0} or udp.SrcPort == {0}", p));
                        }
                        parts.Add("(" + string.Join(" or ", ps.ToArray()) + ")");
                    }
                    if (ipFilter != null)
                    {
                        parts.Add(string.Format("(ip.SrcAddr == {0} or ip.DstAddr == {0})", ipFilter));
                    }
                    if (parts.Count == 0) filter = "ip";
                    else filter = string.Join(" and ", parts.ToArray());
                }
            }

            Console.WriteLine("[*] Output: " + outFile);
            Console.WriteLine("[*] Filter: " + filter);
            Console.WriteLine("[*] Layer: " + (hotspot ? "NETWORK_FORWARD (hotspot/forwarded traffic)" : "NETWORK (local traffic)"));
            if (fullCapture) Console.WriteLine("[*] Mode: FULL (all IP traffic)");
            Console.WriteLine("[*] Duration: " + (duration > 0 ? (duration + "s") : "unlimited (Ctrl+C to stop)"));
            if (statsInterval > 0) Console.WriteLine("[*] Stats interval: " + statsInterval + "s");

            IntPtr handle = WinDivert.WinDivertOpen(filter, hotspot ? WinDivert.LAYER_NETWORK_FORWARD : WinDivert.LAYER_NETWORK, 0, WinDivert.FLAG_SNIFF | WinDivert.FLAG_RECV_ONLY);
            if (handle == IntPtr.Zero || handle == new IntPtr(-1))
            {
                int err = Marshal.GetLastWin32Error();
                string desc;
                switch (err)
                {
                    case 2: desc = "ERROR_FILE_NOT_FOUND (WinDivert.dll/.sys missing)"; break;
                    case 5: desc = "ERROR_ACCESS_DENIED (need Administrator)"; break;
                    case 31: desc = "ERROR_GEN_FAILURE (driver init failed)"; break;
                    case 87: desc = "ERROR_INVALID_PARAMETER (bad filter syntax)"; break;
                    default: desc = "Unknown error"; break;
                }
                Console.WriteLine("[!] WinDivertOpen failed (error " + err + "): " + desc);
                Console.WriteLine("    Ensure WinDivert.dll and WinDivert64.sys are in the same dir as PacketTool.exe.");
                Console.WriteLine("    Current dir: " + Environment.CurrentDirectory);
                Console.WriteLine("    Exe dir: " + AppDomain.CurrentDomain.BaseDirectory);
                return 2;
            }
            WinDivert.WinDivertSetParam(handle, 2 /*QUEUE_SIZE*/, 64 * 1024 * 1024);
            WinDivert.WinDivertSetParam(handle, 0 /*QUEUE_LENGTH*/, 16384);

            // Ctrl+C handler
            ConsoleCancelEventHandler cancelHandler = (s, e) =>
            {
                e.Cancel = true;
                g_running = false;
                WinDivert.WinDivertShutdown(handle, 1 /* RECV */);
                Console.WriteLine();
                Console.WriteLine("[*] Ctrl+C received, stopping...");
            };
            Console.CancelKeyPress += cancelHandler;
            Timer stopTimer = duration > 0 ? new Timer(delegate { WinDivert.WinDivertShutdown(handle, 1 /* RECV */); }, null, duration * 1000L, Timeout.Infinite) : null;
            Timer stopFileTimer = stopFile != null ? new Timer(delegate {
                if (File.Exists(stopFile)) WinDivert.WinDivertShutdown(handle, 1 /* RECV */);
            }, null, 200, 200) : null;

            Console.WriteLine("[*] WinDivert opened. Capturing... (Ctrl+C to stop)");

            // Stats tracking
            var flowStats = new Dictionary<string, long>(); // flowKey -> byte count
            long lastStatsTs = 0;
            long startTs = Stopwatch.GetTimestamp();
            long count = 0;
            long totalBytes = 0;
            long lastFlushTs = startTs;

            using (var pw = new PcapWriter(outFile))
            {
                byte[] buf = new byte[65535];
                while (g_running)
                {
                    if (duration > 0)
                    {
                        double elapsed = (Stopwatch.GetTimestamp() - startTs) / (double)Stopwatch.Frequency;
                        if (elapsed >= duration) { Console.WriteLine("[*] Duration reached."); break; }
                    }
                    // Non-blocking check: WinDivertRecv is blocking, but CancelKeyPress will close handle
                    uint recvLen;
                    WinDivert.WINDIVERT_ADDRESS addr;
                    bool ok = WinDivert.WinDivertRecv(handle, buf, (uint)buf.Length, out recvLen, out addr);
                    if (!g_running) break;
                    if (!ok)
                    {
                        int err = Marshal.GetLastWin32Error();
                        if (err == 995 /*ERROR_OPERATION_ABORTED*/ || err == 232 /*ERROR_NO_DATA*/) break;
                        Console.WriteLine("[!] WinDivertRecv error " + err);
                        break;
                    }
                    if (recvLen > 0)
                    {
                        long timestampMicros = (DateTime.UtcNow.Ticks - 621355968000000000L) / 10;
                        pw.WritePacket(buf, (int)recvLen, timestampMicros);
                        long flushTs = Stopwatch.GetTimestamp();
                        if (flushTs - lastFlushTs >= Stopwatch.Frequency) { pw.Flush(); lastFlushTs = flushTs; }
                        if (hexOutput) Console.WriteLine("PACKET_HEX:" + BitConverter.ToString(buf, 0, (int)recvLen).Replace("-", ""));
                        count++;
                        totalBytes += recvLen;
                        // Track flow stats
                        var ip = IpPacket.Parse(buf, (int)recvLen);
                        if (ip != null)
                        {
                            var seg = ParseSegment(ip, timestampMicros);
                            if (seg != null)
                            {
                                string key = seg.FlowKey;
                                long cur;
                                flowStats.TryGetValue(key, out cur);
                                flowStats[key] = cur + seg.Payload.Length;
                            }
                        }
                        if (count % 500 == 0)
                        {
                            Console.Write(string.Format("\r[*] Captured {0} packets ({1} bytes), {2} flows   ",
                                count, totalBytes, flowStats.Count));
                        }
                        // Periodic stats
                        if (statsInterval > 0)
                        {
                            long nowTs = Stopwatch.GetTimestamp();
                            double sinceStats = (nowTs - lastStatsTs) / (double)Stopwatch.Frequency;
                            if (lastStatsTs == 0) lastStatsTs = nowTs;
                            else if (sinceStats >= statsInterval)
                            {
                                lastStatsTs = nowTs;
                                PrintFlowStats(flowStats);
                            }
                        }
                    }
                }
            }
            if (stopTimer != null) stopTimer.Dispose();
            if (stopFileTimer != null) stopFileTimer.Dispose();
            Console.CancelKeyPress -= cancelHandler;
            WinDivert.WinDivertClose(handle);
            Console.WriteLine();
            Console.WriteLine(string.Format("[*] Done. {0} packets, {1} bytes, {2} flows -> {3}",
                count, totalBytes, flowStats.Count, outFile));
            // Final stats
            if (statsInterval > 0 || flowStats.Count > 0)
            {
                PrintFlowStats(flowStats, true);
            }
            return 0;
        }

        static void PrintFlowStats(Dictionary<string, long> flowStats, bool final = false)
        {
            Console.WriteLine();
            Console.WriteLine(string.Format("--- {0} Flow Stats ({1} flows) ---",
                final ? "FINAL" : "PERIODIC", flowStats.Count));
            var sorted = flowStats.OrderByDescending(kv => kv.Value).Take(20).ToList();
            foreach (var kv in sorted)
            {
                Console.WriteLine(string.Format("  {0,12} bytes  {1}", kv.Value, kv.Key));
            }
            Console.WriteLine("---");
        }

        // ============ Segment parsing (TCP + UDP) ============
        static Segment ParseSegment(IpPacket ip, long tsMicros)
        {
            if (ip == null) return null;
            byte[] d = ip.Payload;
            if (d.Length < 4) return null;
            if (ip.Protocol == 6) // TCP
            {
                if (d.Length < 20) return null;
                ushort sp = (ushort)((d[0] << 8) | d[1]);
                ushort dp = (ushort)((d[2] << 8) | d[3]);
                uint seq = (uint)((d[4] << 24) | (d[5] << 16) | (d[6] << 8) | d[7]);
                int dataOff = ((d[12] >> 4) & 0xF) * 4;
                byte flags = d[13];
                if (dataOff < 20 || dataOff > d.Length) dataOff = 20;
                byte[] payload = new byte[d.Length - dataOff];
                Array.Copy(d, dataOff, payload, 0, payload.Length);
                return new Segment
                {
                    SrcIp = ip.SrcIp, DstIp = ip.DstIp,
                    SrcPort = sp, DstPort = dp,
                    Seq = seq, Flags = flags,
                    Protocol = 6, Payload = payload, TsMicros = tsMicros
                };
            }
            else if (ip.Protocol == 17) // UDP
            {
                if (d.Length < 8) return null;
                ushort sp = (ushort)((d[0] << 8) | d[1]);
                ushort dp = (ushort)((d[2] << 8) | d[3]);
                int udpLen = (d[4] << 8) | d[5];
                if (udpLen < 8 || udpLen > d.Length) udpLen = d.Length;
                byte[] payload = new byte[udpLen - 8];
                Array.Copy(d, 8, payload, 0, payload.Length);
                return new Segment
                {
                    SrcIp = ip.SrcIp, DstIp = ip.DstIp,
                    SrcPort = sp, DstPort = dp,
                    Seq = 0, Flags = 0,
                    Protocol = 17, Payload = payload, TsMicros = tsMicros
                };
            }
            return null;
        }

        // ============ compare mode ============
        static int RunCompare(string[] args)
        {
            if (args.Length < 3)
            {
                Console.WriteLine("Usage: compare <f1.pcap> <f2.pcap> [--report <out.txt>] [--port <p>] [--detail] [--flow <key>] [--bin <prefix>]");
                return 1;
            }
            string f1 = args[1], f2 = args[2];
            string reportFile = null;
            int portFilter = 0;
            bool detail = false;
            string flowFilter = null;
            string binPrefix = null;
            for (int i = 3; i < args.Length; i++)
            {
                if (args[i] == "--report" && i + 1 < args.Length) reportFile = args[++i];
                else if (args[i] == "--port" && i + 1 < args.Length) portFilter = int.Parse(args[++i]);
                else if (args[i] == "--detail") detail = true;
                else if (args[i] == "--flow" && i + 1 < args.Length) flowFilter = args[++i];
                else if (args[i] == "--bin" && i + 1 < args.Length) binPrefix = args[++i];
            }

            Console.WriteLine("[*] Loading " + f1);
            var flows1 = LoadPcapFlows(f1, portFilter);
            Console.WriteLine(string.Format("    {0} flows, {1} packets", flows1.Count, CountPackets(flows1)));
            Console.WriteLine("[*] Loading " + f2);
            var flows2 = LoadPcapFlows(f2, portFilter);
            Console.WriteLine(string.Format("    {0} flows, {1} packets", flows2.Count, CountPackets(flows2)));

            var sb = new StringBuilder();
            sb.AppendLine("=== Packet Byte Comparison Report ===");
            sb.AppendLine("File A: " + f1);
            sb.AppendLine("File B: " + f2);
            sb.AppendLine(string.Format("Flows A: {0}, Flows B: {1}", flows1.Count, flows2.Count));
            sb.AppendLine("");

            // Get all flow keys
            var allKeys = new HashSet<string>();
            foreach (var k in flows1.Keys) allKeys.Add(k);
            foreach (var k in flows2.Keys) allKeys.Add(k);

            int onlyA = 0, onlyB = 0, sameFlows = 0, diffFlows = 0;
            int binIdx = 0;

            foreach (var key in allKeys)
            {
                if (flowFilter != null && !key.Contains(flowFilter)) continue;

                bool inA = flows1.ContainsKey(key);
                bool inB = flows2.ContainsKey(key);
                if (inA && !inB)
                {
                    onlyA++;
                    var flow = flows1[key];
                    sb.AppendLine(string.Format("[ONLY-A] {0}  (packets={1}, bytes={2})",
                        key, flow.Count, FlowBytes(flow)));
                    if (binPrefix != null)
                    {
                        ExportFlowBin(binPrefix + "_onlyA_" + (binIdx++) + ".bin", flow);
                    }
                }
                else if (!inA && inB)
                {
                    onlyB++;
                    var flow = flows2[key];
                    sb.AppendLine(string.Format("[ONLY-B] {0}  (packets={1}, bytes={2})",
                        key, flow.Count, FlowBytes(flow)));
                    if (binPrefix != null)
                    {
                        ExportFlowBin(binPrefix + "_onlyB_" + (binIdx++) + ".bin", flow);
                    }
                }
                else
                {
                    var flowA = flows1[key];
                    var flowB = flows2[key];
                    // Determine client/server from SYN
                    var cs = DetermineClientServer(flowA, flowB);
                    uint cIp = cs.Item1; ushort cPort = cs.Item2;
                    uint sIp = cs.Item3; ushort sPort = cs.Item4;

                    bool flowDiff = false;
                    foreach (var dir in new string[] { "c2s", "s2c" })
                    {
                        var reasmA = ReassembleDirection(flowA, dir, cIp, cPort, sIp, sPort);
                        var reasmB = ReassembleDirection(flowB, dir, cIp, cPort, sIp, sPort);
                        if (reasmA.Length == 0 && reasmB.Length == 0) continue;
                        if (reasmA.Length != reasmB.Length || !BytesEqual(reasmA, reasmB))
                        {
                            flowDiff = true;
                            diffFlows++;
                            sb.AppendLine(string.Format("[DIFF] {0} dir={1}  lenA={2} lenB={3}",
                                key, dir, reasmA.Length, reasmB.Length));
                            DumpDiff(sb, reasmA, reasmB, detail);
                            if (binPrefix != null)
                            {
                                File.WriteAllBytes(binPrefix + "_diff_" + binIdx + "_" + dir + "_A.bin", reasmA);
                                File.WriteAllBytes(binPrefix + "_diff_" + binIdx + "_" + dir + "_B.bin", reasmB);
                            }
                        }
                    }
                    binIdx++;
                    if (!flowDiff)
                    {
                        sameFlows++;
                        if (detail)
                        {
                            sb.AppendLine(string.Format("[SAME] {0}  (packets A={1} B={2})", key, flowA.Count, flowB.Count));
                        }
                    }
                }
            }

            sb.AppendLine("");
            sb.AppendLine("=== Summary ===");
            sb.AppendLine(string.Format("Total flows: {0}", allKeys.Count));
            sb.AppendLine(string.Format("Only in A: {0}", onlyA));
            sb.AppendLine(string.Format("Only in B: {0}", onlyB));
            sb.AppendLine(string.Format("Same: {0}", sameFlows));
            sb.AppendLine(string.Format("Different: {0}", diffFlows));
            if (flowFilter != null) sb.AppendLine(string.Format("Flow filter: {0}", flowFilter));

            string report = sb.ToString();
            Console.WriteLine(report);
            if (reportFile != null)
            {
                File.WriteAllText(reportFile, report);
                Console.WriteLine("[*] Report saved to: " + reportFile);
            }
            return 0;
        }

        // Determine client/server by looking for SYN (no SYN-ACK)
        static Tuple<uint, ushort, uint, ushort> DetermineClientServer(List<Segment> flowA, List<Segment> flowB)
        {
            // Combine all segments from both flows
            var all = new List<Segment>(flowA);
            all.AddRange(flowB);
            // Look for pure SYN
            foreach (var s in all)
            {
                if (s.Protocol == 6 && (s.Flags & 0x02) != 0 && (s.Flags & 0x10) == 0)
                {
                    return Tuple.Create(s.SrcIp, s.SrcPort, s.DstIp, s.DstPort);
                }
            }
            // Fallback: first TCP segment's src is client; if no TCP, first UDP segment's src
            foreach (var s in all)
            {
                if (s.Payload.Length > 0) return Tuple.Create(s.SrcIp, s.SrcPort, s.DstIp, s.DstPort);
            }
            if (all.Count > 0) return Tuple.Create(all[0].SrcIp, all[0].SrcPort, all[0].DstIp, all[0].DstPort);
            return Tuple.Create(0u, (ushort)0, 0u, (ushort)0);
        }

        static Dictionary<string, List<Segment>> LoadPcapFlows(string path, int portFilter)
        {
            var flows = new Dictionary<string, List<Segment>>();
            using (var pr = new PcapReader(path))
            {
                long ts;
                byte[] data;
                while ((data = pr.ReadPacket(out ts)) != null)
                {
                    var ip = IpPacket.Parse(data, data.Length);
                    if (ip == null) continue;
                    var seg = ParseSegment(ip, ts);
                    if (seg == null) continue;
                    if (portFilter > 0 && seg.SrcPort != portFilter && seg.DstPort != portFilter) continue;
                    string key = seg.FlowKey;
                    if (!flows.ContainsKey(key)) flows[key] = new List<Segment>();
                    flows[key].Add(seg);
                }
            }
            return flows;
        }

        static int CountPackets(Dictionary<string, List<Segment>> flows)
        {
            int n = 0;
            foreach (var kv in flows) n += kv.Value.Count;
            return n;
        }

        static long FlowBytes(List<Segment> segs)
        {
            long n = 0;
            foreach (var s in segs) n += s.Payload.Length;
            return n;
        }

        static byte[] ReassembleDirection(List<Segment> segs, string dirHint,
                                          uint cIp, ushort cPort, uint sIp, ushort sPort)
        {
            // Filter segments matching the requested direction
            var dirSegs = new List<Segment>();
            foreach (var s in segs)
            {
                if (dirHint == "c2s")
                {
                    if (s.SrcIp == cIp && s.SrcPort == cPort && s.DstIp == sIp && s.DstPort == sPort)
                        dirSegs.Add(s);
                }
                else // s2c
                {
                    if (s.SrcIp == sIp && s.SrcPort == sPort && s.DstIp == cIp && s.DstPort == cPort)
                        dirSegs.Add(s);
                }
            }
            if (dirSegs.Count == 0) return new byte[0];

            // For UDP: just concatenate payloads by timestamp
            if (dirSegs[0].Protocol == 17)
            {
                dirSegs.Sort((a, b) => a.TsMicros.CompareTo(b.TsMicros));
                var result = new List<byte>();
                foreach (var s in dirSegs) result.AddRange(s.Payload);
                return result.ToArray();
            }

            // For TCP: reassemble by SEQ
            dirSegs.Sort((a, b) => a.Seq.CompareTo(b.Seq));
            var bytes = new List<byte>();
            uint expected = 0;
            bool first = true;
            foreach (var seg in dirSegs)
            {
                if (seg.Payload.Length == 0) continue;
                if ((seg.Flags & 0x02) != 0) { expected = seg.Seq + 1; first = false; continue; }
                if (first) { expected = seg.Seq; first = false; }
                long offset = (long)seg.Seq - expected;
                if (offset < 0)
                {
                    int skip = (int)(-offset);
                    if (skip >= seg.Payload.Length) continue;
                    var np = new byte[seg.Payload.Length - skip];
                    Array.Copy(seg.Payload, skip, np, 0, np.Length);
                    bytes.AddRange(np);
                    expected = seg.Seq + (uint)seg.Payload.Length;
                }
                else if (offset == bytes.Count)
                {
                    bytes.AddRange(seg.Payload);
                    expected = seg.Seq + (uint)seg.Payload.Length;
                }
                else if (offset > bytes.Count)
                {
                    while (bytes.Count < offset) bytes.Add(0);
                    bytes.AddRange(seg.Payload);
                    expected = seg.Seq + (uint)seg.Payload.Length;
                }
                else
                {
                    int startInStream = (int)offset;
                    int copyLen = Math.Min(seg.Payload.Length, bytes.Count - startInStream);
                    if (copyLen < seg.Payload.Length)
                    {
                        byte[] extra = new byte[seg.Payload.Length - copyLen];
                        Array.Copy(seg.Payload, copyLen, extra, 0, extra.Length);
                        bytes.AddRange(extra);
                    }
                    expected = seg.Seq + (uint)seg.Payload.Length;
                }
            }
            return bytes.ToArray();
        }

        static bool BytesEqual(byte[] a, byte[] b)
        {
            if (a.Length != b.Length) return false;
            for (int i = 0; i < a.Length; i++) if (a[i] != b[i]) return false;
            return true;
        }

        static void DumpDiff(StringBuilder sb, byte[] a, byte[] b, bool detail)
        {
            int minLen = Math.Min(a.Length, b.Length);
            int diffCount = 0;
            int firstDiff = -1;
            for (int i = 0; i < minLen; i++)
            {
                if (a[i] != b[i])
                {
                    diffCount++;
                    if (firstDiff < 0) firstDiff = i;
                }
            }
            int extra = Math.Abs(a.Length - b.Length);
            sb.AppendLine(string.Format("  First diff at byte: {0} (0x{0:X})", firstDiff));
            sb.AppendLine(string.Format("  Different bytes (overlap region): {0}", diffCount));
            sb.AppendLine(string.Format("  Length diff: {0} bytes", extra));

            if (firstDiff >= 0 && detail)
            {
                int ctxStart = Math.Max(0, firstDiff - 16);
                int ctxEnd = Math.Min(minLen, firstDiff + 64);
                sb.AppendLine("  --- Context (A) at offset " + ctxStart + " ---");
                sb.AppendLine("  " + HexDump(a, ctxStart, ctxEnd));
                sb.AppendLine("  --- Context (B) at offset " + ctxStart + " ---");
                sb.AppendLine("  " + HexDump(b, ctxStart, ctxEnd));
                // Also dump full hex if total length is small
                if (a.Length + b.Length < 1024)
                {
                    sb.AppendLine("  --- Full A (" + a.Length + " bytes) ---");
                    sb.AppendLine("  " + HexDump(a, 0, a.Length));
                    sb.AppendLine("  --- Full B (" + b.Length + " bytes) ---");
                    sb.AppendLine("  " + HexDump(b, 0, b.Length));
                }
            }
            else if (firstDiff >= 0)
            {
                int ctxStart = Math.Max(0, firstDiff - 8);
                int ctxEnd = Math.Min(minLen, firstDiff + 32);
                sb.AppendLine("  A[off " + ctxStart + "]: " + HexDump(a, ctxStart, ctxEnd));
                sb.AppendLine("  B[off " + ctxStart + "]: " + HexDump(b, ctxStart, ctxEnd));
            }
        }

        static string HexDump(byte[] data, int start, int end)
        {
            var sb = new StringBuilder();
            for (int i = start; i < end && i < data.Length; i++)
            {
                sb.Append(data[i].ToString("X2"));
                sb.Append(' ');
            }
            sb.Append(" | ");
            for (int i = start; i < end && i < data.Length; i++)
            {
                byte c = data[i];
                sb.Append((c >= 0x20 && c < 0x7F) ? (char)c : '.');
            }
            return sb.ToString();
        }

        static void ExportFlowBin(string path, List<Segment> segs)
        {
            var bytes = new List<byte>();
            // Sort by timestamp and concatenate all payloads (both directions combined)
            var sorted = new List<Segment>(segs);
            sorted.Sort((a, b) => a.TsMicros.CompareTo(b.TsMicros));
            foreach (var s in sorted) bytes.AddRange(s.Payload);
            File.WriteAllBytes(path, bytes.ToArray());
            Console.WriteLine("[*] Exported flow bin: " + path + " (" + bytes.Count + " bytes)");
        }

        // ============ dumpflow mode: export all packets matching (ip,port) ============
        static int RunDumpFlow(string[] args)
        {
            if (args.Length < 4)
            {
                Console.WriteLine("Usage: dumpflow <pcap> <ip> <port> [--out <base>]");
                Console.WriteLine("  Exports c2s.bin, s2c.bin, c2s.txt, s2c.txt for the flow");
                return 1;
            }
            string pcapFile = args[1];
            string ip = args[2];
            int port;
            if (!int.TryParse(args[3], out port))
            {
                Console.WriteLine("[!] Invalid port: " + args[3]);
                return 1;
            }
            string outBase = Path.GetFileNameWithoutExtension(pcapFile) + "_" + ip.Replace('.', '_') + "_" + port;
            for (int i = 4; i < args.Length; i++)
            {
                if (args[i] == "--out" && i + 1 < args.Length) outBase = args[++i];
            }

            // Parse target IP
            uint targetIp = 0;
            try
            {
                string[] parts = ip.Split('.');
                if (parts.Length != 4) throw new Exception();
                targetIp = (uint)((int.Parse(parts[0]) << 24) | (int.Parse(parts[1]) << 16) |
                                   (int.Parse(parts[2]) << 8) | int.Parse(parts[3]));
            }
            catch
            {
                Console.WriteLine("[!] Invalid IP: " + ip);
                return 1;
            }

            Console.WriteLine("[*] Loading " + pcapFile);
            var flows = LoadPcapFlows(pcapFile, port);
            Console.WriteLine("[*] Total flows with port " + port + ": " + flows.Count);

            // Find flows matching the IP
            List<Segment> targetFlow = null;
            foreach (var kv in flows)
            {
                foreach (var s in kv.Value)
                {
                    if (s.SrcIp == targetIp || s.DstIp == targetIp)
                    {
                        targetFlow = kv.Value;
                        break;
                    }
                }
                if (targetFlow != null) break;
            }
            if (targetFlow == null)
            {
                Console.WriteLine("[!] No flow found with IP=" + ip + " port=" + port);
                return 2;
            }

            var cs = DetermineClientServer(targetFlow, new List<Segment>());
            uint cIp = cs.Item1; ushort cPort = cs.Item2;
            uint sIp = cs.Item3; ushort sPort = cs.Item4;
            // If target IP is server side, swap so output names are correct
            if (sIp != targetIp && cIp != targetIp)
            {
                // shouldn't happen, but be safe
            }

            Console.WriteLine(string.Format("[*] Flow: client {0}:{1} <-> server {2}:{3}",
                IpPacket.IpToStr(cIp), cPort, IpPacket.IpToStr(sIp), sPort));

            var c2s = ReassembleDirection(targetFlow, "c2s", cIp, cPort, sIp, sPort);
            var s2c = ReassembleDirection(targetFlow, "s2c", cIp, cPort, sIp, sPort);

            string c2sBin = outBase + "_c2s.bin";
            string s2cBin = outBase + "_s2c.bin";
            string c2sTxt = outBase + "_c2s.txt";
            string s2cTxt = outBase + "_s2c.txt";

            File.WriteAllBytes(c2sBin, c2s);
            File.WriteAllBytes(s2cBin, s2c);
            File.WriteAllText(c2sTxt, HexDump(c2s, 0, c2s.Length));
            File.WriteAllText(s2cTxt, HexDump(s2c, 0, s2c.Length));

            Console.WriteLine("[OK] Exported:");
            Console.WriteLine("  " + c2sBin + " (" + c2s.Length + " bytes)");
            Console.WriteLine("  " + s2cBin + " (" + s2c.Length + " bytes)");
            Console.WriteLine("  " + c2sTxt);
            Console.WriteLine("  " + s2cTxt);
            return 0;
        }
    }
}
