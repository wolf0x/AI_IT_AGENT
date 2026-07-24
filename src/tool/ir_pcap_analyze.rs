//! PCAP/PCAPNG quick analysis tool — offline packet capture security analysis.
//!
//! Parses pcap/pcapng files using pcap-parser, performs manual L2-L4 protocol
//! dissection, flow tracking, DNS/HTTP extraction, and suspicious pattern detection.
//! Designed for rapid triage of capture files during incident response.

use async_trait::async_trait;
use serde_json::{json, Value};
use std::collections::HashMap;
use std::fs::File;
use std::io::BufReader;

use super::Tool;
use crate::context::ToolContext;
use crate::error::AgentResult;

use pcap_parser::{PcapBlockOwned, PcapError};
use pcap_parser::traits::PcapNGPacketBlock;

/// Maximum packets to analyze (safety limit for huge captures).
const MAX_PACKETS: u64 = 2_000_000;

/// Maximum entries to collect per category (prevents unbounded memory growth).
const MAX_SUSPICIOUS: usize = 200;
const MAX_FLOWS: usize = 50_000;
const MAX_DNS_ENTRIES: usize = 10_000;
const MAX_HTTP_ENTRIES: usize = 10_000;

/// Ports commonly associated with backdoors, C2, and suspicious services.
const SUSPICIOUS_PORTS: &[u16] = &[
    4444, 5555, 6666, 6667, 7777, 8888, 9999, 12345, 27374, 31337, 1234, 4321, 54321, 1212,
    3128, 1080, 9050, 9051,
];

// ── Protocol parsing ────────────────────────────────────────────

/// Parsed L3/L4 packet info.
struct PacketInfo {
    src_ip: String,
    dst_ip: String,
    proto: u8,        // 6=TCP, 17=UDP, 1=ICMP, 58=ICMPv6
    src_port: u16,
    dst_port: u16,
    payload: Vec<u8>, // L4 payload (TCP/UDP only)
    ip_version: u8,   // 4 or 6
    total_len: usize,  // IP total length (or captured length)
}

/// Parse Ethernet frame → extract EtherType and payload.
/// Handles 802.1Q VLAN tags (0x8100).
fn parse_ethernet(data: &[u8]) -> Option<(u16, &[u8])> {
    if data.len() < 14 {
        return None;
    }
    let mut ethertype = u16::from_be_bytes([data[12], data[13]]);
    let mut offset = 14;

    // Handle 802.1Q VLAN tag
    if ethertype == 0x8100 {
        if data.len() < 18 {
            return None;
        }
        ethertype = u16::from_be_bytes([data[16], data[17]]);
        offset = 18;
    }

    Some((ethertype, &data[offset..]))
}

/// Parse IPv4 header → extract packet info.
fn parse_ipv4(data: &[u8]) -> Option<PacketInfo> {
    if data.len() < 20 {
        return None;
    }
    let ihl = (data[0] & 0x0F) as usize * 4;
    if ihl < 20 || data.len() < ihl {
        return None;
    }
    let total_len = u16::from_be_bytes([data[2], data[3]]) as usize;
    let proto = data[9];
    let src = format!("{}.{}.{}.{}", data[12], data[13], data[14], data[15]);
    let dst = format!("{}.{}.{}.{}", data[16], data[17], data[18], data[19]);

    let l4_data = if total_len >= ihl && data.len() >= total_len {
        &data[ihl..total_len]
    } else if data.len() > ihl {
        &data[ihl..]
    } else {
        return None;
    };

    let (src_port, dst_port, payload) = parse_l4(proto, l4_data);

    Some(PacketInfo {
        src_ip: src,
        dst_ip: dst,
        proto,
        src_port,
        dst_port,
        payload,
        ip_version: 4,
        total_len: total_len.max(ihl + l4_data.len()),
    })
}

/// Parse IPv6 header (fixed 40 bytes) → extract packet info.
fn parse_ipv6(data: &[u8]) -> Option<PacketInfo> {
    if data.len() < 40 {
        return None;
    }
    let payload_len = u16::from_be_bytes([data[4], data[5]]) as usize;
    let next_header = data[6];
    let src = format_ipv6(&data[8..24]);
    let dst = format_ipv6(&data[24..40]);

    let l4_data = if data.len() >= 40 + payload_len {
        &data[40..40 + payload_len]
    } else if data.len() > 40 {
        &data[40..]
    } else {
        &[]
    };

    let (src_port, dst_port, payload) = parse_l4(next_header, l4_data);

    Some(PacketInfo {
        src_ip: src,
        dst_ip: dst,
        proto: next_header,
        src_port,
        dst_port,
        payload,
        ip_version: 6,
        total_len: 40 + payload_len,
    })
}

/// Format 16 bytes as IPv6 address string (simplified, no :: compression).
fn format_ipv6(bytes: &[u8]) -> String {
    let groups: Vec<String> = (0..8)
        .map(|i| format!("{:x}", u16::from_be_bytes([bytes[i * 2], bytes[i * 2 + 1]])))
        .collect();
    groups.join(":")
}

/// Parse L4 header (TCP/UDP) → extract (src_port, dst_port, payload).
fn parse_l4(proto: u8, data: &[u8]) -> (u16, u16, Vec<u8>) {
    match proto {
        6 => {
            // TCP: src_port(2) + dst_port(2) + seq(4) + ack(4) + data_offset(1) + ...
            if data.len() < 20 {
                return (0, 0, Vec::new());
            }
            let src_port = u16::from_be_bytes([data[0], data[1]]);
            let dst_port = u16::from_be_bytes([data[2], data[3]]);
            let data_offset = ((data[12] >> 4) as usize) * 4;
            let payload = if data.len() > data_offset {
                data[data_offset..].to_vec()
            } else {
                Vec::new()
            };
            (src_port, dst_port, payload)
        }
        17 => {
            // UDP: src_port(2) + dst_port(2) + length(2) + checksum(2) + payload
            if data.len() < 8 {
                return (0, 0, Vec::new());
            }
            let src_port = u16::from_be_bytes([data[0], data[1]]);
            let dst_port = u16::from_be_bytes([data[2], data[3]]);
            let payload = data[8..].to_vec();
            (src_port, dst_port, payload)
        }
        _ => (0, 0, Vec::new()),
    }
}

// ── DNS parsing ─────────────────────────────────────────────────

/// Parse DNS query from wire format. Returns (domain, qtype_str).
/// Only processes queries (QR=0), skips responses.
fn parse_dns_query_name(payload: &[u8]) -> Option<(String, String)> {
    // DNS header: 12 bytes minimum
    if payload.len() < 12 {
        return None;
    }
    let flags = u16::from_be_bytes([payload[2], payload[3]]);
    if flags & 0x8000 != 0 {
        return None; // response, not query
    }
    let qdcount = u16::from_be_bytes([payload[4], payload[5]]);
    if qdcount == 0 {
        return None;
    }

    // Parse first question's QNAME
    let mut pos = 12;
    let mut labels = Vec::new();
    loop {
        if pos >= payload.len() {
            return None;
        }
        let len = payload[pos] as usize;
        if len == 0 {
            pos += 1;
            break;
        }
        // Compression pointer (shouldn't appear in queries, but guard against it)
        if len & 0xC0 == 0xC0 {
            pos += 2;
            break;
        }
        pos += 1;
        if pos + len > payload.len() {
            return None;
        }
        if let Ok(label) = std::str::from_utf8(&payload[pos..pos + len]) {
            labels.push(label.to_string());
        }
        pos += len;
    }

    // QTYPE (2 bytes)
    if pos + 2 > payload.len() {
        return None;
    }
    let qtype = u16::from_be_bytes([payload[pos], payload[pos + 1]]);
    let qtype_str = match qtype {
        1 => "A",
        2 => "NS",
        5 => "CNAME",
        6 => "SOA",
        12 => "PTR",
        15 => "MX",
        16 => "TXT",
        28 => "AAAA",
        33 => "SRV",
        65 => "HTTPS",
        255 => "ANY",
        _ => "OTHER",
    };

    if labels.is_empty() {
        return None;
    }
    Some((labels.join("."), qtype_str.to_string()))
}

// ── HTTP parsing ────────────────────────────────────────────────

/// Detect HTTP request and extract (method, host, path).
fn parse_http_request(payload: &[u8]) -> Option<(String, String, String)> {
    if payload.len() < 14 {
        return None;
    }
    let methods: &[(&[u8], &str)] = &[
        (b"GET ", "GET"),
        (b"POST ", "POST"),
        (b"PUT ", "PUT"),
        (b"DELETE ", "DELETE"),
        (b"HEAD ", "HEAD"),
        (b"OPTIONS ", "OPTIONS"),
        (b"PATCH ", "PATCH"),
        (b"CONNECT ", "CONNECT"),
        (b"TRACE ", "TRACE"),
    ];

    let method = methods.iter().find(|(prefix, _)| payload.starts_with(prefix))?;
    let method_str = method.1.to_string();

    // Find end of request line
    let line_end = payload
        .windows(2)
        .position(|w| w == b"\r\n")
        .unwrap_or(payload.len());
    let request_line = String::from_utf8_lossy(&payload[..line_end]);
    let parts: Vec<&str> = request_line.split_whitespace().collect();
    let path = parts.get(1).unwrap_or(&"/").to_string();

    // Extract Host header
    let header_text = String::from_utf8_lossy(payload);
    let host = header_text
        .lines()
        .find_map(|line| {
            let lower = line.to_lowercase();
            if lower.starts_with("host:") {
                Some(line[5..].trim().to_string())
            } else {
                None
            }
        })
        .unwrap_or_default();

    Some((method_str, host, path))
}

// ── Port-to-service mapping ─────────────────────────────────────

fn port_to_service(port: u16) -> &'static str {
    match port {
        20 => "ftp-data",
        21 => "ftp",
        22 => "ssh",
        23 => "telnet",
        25 => "smtp",
        53 => "dns",
        67 | 68 => "dhcp",
        69 => "tftp",
        80 => "http",
        110 => "pop3",
        111 => "rpcbind",
        123 => "ntp",
        135 => "msrpc",
        137 | 138 => "netbios",
        139 => "netbios-ssn",
        143 => "imap",
        161 | 162 => "snmp",
        389 => "ldap",
        443 => "https",
        445 => "smb",
        465 => "smtps",
        514 => "syslog",
        587 => "submission",
        636 => "ldaps",
        993 => "imaps",
        995 => "pop3s",
        1080 => "socks",
        1433 => "mssql",
        1521 => "oracle",
        2049 => "nfs",
        3306 => "mysql",
        3389 => "rdp",
        5432 => "postgresql",
        5900 => "vnc",
        6379 => "redis",
        8080 => "http-alt",
        8443 => "https-alt",
        9090 => "webconsole",
        27017 => "mongodb",
        _ => "unknown",
    }
}

// ── Flow tracking ───────────────────────────────────────────────

#[derive(Hash, Eq, PartialEq, Clone)]
struct FlowKey {
    src_ip: String,
    dst_ip: String,
    proto: u8,
    src_port: u16,
    dst_port: u16,
}

struct FlowStats {
    packets: u64,
    bytes: u64,
}

// ── Analysis engine ─────────────────────────────────────────────

struct PcapAnalysis {
    total_packets: u64,
    total_bytes: u64,
    first_ts: u64, // nanoseconds
    last_ts: u64,
    proto_tcp: u64,
    proto_udp: u64,
    proto_icmp: u64,
    proto_other: u64,
    ipv4_count: u64,
    ipv6_count: u64,
    talkers: HashMap<String, (u64, u64)>, // ip → (packets, bytes)
    port_stats: HashMap<u16, u64>,        // dst_port → packets
    flows: HashMap<FlowKey, FlowStats>,
    dns_queries: HashMap<String, u64>,    // "name|type" → count
    http_requests: HashMap<String, u64>,  // "method host path" → count
    suspicious: Vec<Value>,
    hourly: HashMap<u8, u64>,             // hour (UTC) → packets
}

impl PcapAnalysis {
    fn new() -> Self {
        Self {
            total_packets: 0,
            total_bytes: 0,
            first_ts: u64::MAX,
            last_ts: 0,
            proto_tcp: 0,
            proto_udp: 0,
            proto_icmp: 0,
            proto_other: 0,
            ipv4_count: 0,
            ipv6_count: 0,
            talkers: HashMap::new(),
            port_stats: HashMap::new(),
            flows: HashMap::new(),
            dns_queries: HashMap::new(),
            http_requests: HashMap::new(),
            suspicious: Vec::new(),
            hourly: HashMap::new(),
        }
    }

    fn process_packet(&mut self, data: &[u8], linktype: pcap_parser::Linktype, ts_ns: u64) {
        self.total_packets += 1;

        // Timestamp tracking
        if ts_ns > 0 {
            if ts_ns < self.first_ts {
                self.first_ts = ts_ns;
            }
            if ts_ns > self.last_ts {
                self.last_ts = ts_ns;
            }
            // Hourly distribution (UTC)
            let secs = ts_ns / 1_000_000_000;
            let hour = ((secs % 86400) / 3600) as u8;
            *self.hourly.entry(hour).or_insert(0) += 1;
        }

        // Parse based on linktype
        let pkt = match linktype.0 {
            1 => {
                // Ethernet
                let (ethertype, payload) = match parse_ethernet(data) {
                    Some(v) => v,
                    None => return,
                };
                self.total_bytes += data.len() as u64;
                match ethertype {
                    0x0800 => parse_ipv4(payload),
                    0x86DD => parse_ipv6(payload),
                    _ => None,
                }
            }
            101 => {
                // Raw IP
                self.total_bytes += data.len() as u64;
                if data.is_empty() {
                    return;
                }
                match data[0] >> 4 {
                    4 => parse_ipv4(data),
                    6 => parse_ipv6(data),
                    _ => None,
                }
            }
            113 => {
                // Linux SLL (cooked capture): 16-byte header, ethertype at offset 14
                if data.len() < 16 {
                    self.total_bytes += data.len() as u64;
                    return;
                }
                let ethertype = u16::from_be_bytes([data[14], data[15]]);
                self.total_bytes += data.len() as u64;
                match ethertype {
                    0x0800 => parse_ipv4(&data[16..]),
                    0x86DD => parse_ipv6(&data[16..]),
                    _ => None,
                }
            }
            _ => {
                self.total_bytes += data.len() as u64;
                return;
            }
        };

        let pkt = match pkt {
            Some(p) => p,
            None => return,
        };

        // IP version stats
        match pkt.ip_version {
            4 => self.ipv4_count += 1,
            6 => self.ipv6_count += 1,
            _ => {}
        }

        // Protocol stats
        match pkt.proto {
            6 => self.proto_tcp += 1,
            17 => self.proto_udp += 1,
            1 | 58 => self.proto_icmp += 1,
            _ => self.proto_other += 1,
        }

        // Talker stats (both src and dst)
        let e = self.talkers.entry(pkt.src_ip.clone()).or_insert((0, 0));
        e.0 += 1;
        e.1 += pkt.total_len as u64;
        let e = self.talkers.entry(pkt.dst_ip.clone()).or_insert((0, 0));
        e.0 += 1;
        e.1 += pkt.total_len as u64;

        // Port stats (destination port only)
        if pkt.dst_port > 0 {
            *self.port_stats.entry(pkt.dst_port).or_insert(0) += 1;
        }

        // Flow tracking (5-tuple)
        let key = FlowKey {
            src_ip: pkt.src_ip.clone(),
            dst_ip: pkt.dst_ip.clone(),
            proto: pkt.proto,
            src_port: pkt.src_port,
            dst_port: pkt.dst_port,
        };
        let flow = self.flows.entry(key).or_insert(FlowStats { packets: 0, bytes: 0 });
        flow.packets += 1;
        flow.bytes += pkt.total_len as u64;
        // Prevent unbounded flow table growth
        if self.flows.len() > MAX_FLOWS {
            self.flows.clear();
        }

        // DNS analysis (UDP port 53)
        if pkt.proto == 17 && (pkt.dst_port == 53 || pkt.src_port == 53) && !pkt.payload.is_empty()
        {
            if self.dns_queries.len() < MAX_DNS_ENTRIES {
                if let Some((name, qtype)) = parse_dns_query_name(&pkt.payload) {
                    let key = format!("{}|{}", name, qtype);
                    *self.dns_queries.entry(key).or_insert(0) += 1;
                }
            }
        }

        // HTTP analysis (TCP port 80 or 8080)
        if pkt.proto == 6
            && (pkt.dst_port == 80 || pkt.dst_port == 8080)
            && !pkt.payload.is_empty()
        {
            if self.http_requests.len() < MAX_HTTP_ENTRIES {
                if let Some((method, host, path)) = parse_http_request(&pkt.payload) {
                    let key = format!("{} {} {}", method, host, path);
                    *self.http_requests.entry(key).or_insert(0) += 1;
                }
            }
        }

        // Suspicious port detection (capped)
        if self.suspicious.len() < MAX_SUSPICIOUS {
            if SUSPICIOUS_PORTS.contains(&pkt.dst_port) {
                self.suspicious.push(json!({
                    "type": "suspicious_port",
                    "detail": format!("Connection to port {} ({})", pkt.dst_port, port_to_service(pkt.dst_port)),
                    "src": format!("{}:{}", pkt.src_ip, pkt.src_port),
                    "dst": format!("{}:{}", pkt.dst_ip, pkt.dst_port),
                }));
            }
            if SUSPICIOUS_PORTS.contains(&pkt.src_port) {
                self.suspicious.push(json!({
                    "type": "suspicious_port",
                    "detail": format!("Traffic from port {} ({})", pkt.src_port, port_to_service(pkt.src_port)),
                    "src": format!("{}:{}", pkt.src_ip, pkt.src_port),
                    "dst": format!("{}:{}", pkt.dst_ip, pkt.dst_port),
                }));
            }
        }
    }

    fn to_json(&self, file_path: &str) -> Value {
        // Duration
        let duration_secs = if self.last_ts > self.first_ts && self.first_ts != u64::MAX {
            (self.last_ts - self.first_ts) / 1_000_000_000
        } else {
            0
        };

        // Top talkers (by bytes, top 10)
        let mut talkers: Vec<_> = self.talkers.iter().collect();
        talkers.sort_by(|a, b| b.1 .1.cmp(&a.1 .1));
        let top_talkers: Vec<Value> = talkers
            .iter()
            .take(10)
            .map(|(ip, (pkts, bytes))| json!({"ip": ip, "packets": pkts, "bytes": bytes}))
            .collect();

        // Top ports (by packets, top 15)
        let mut ports: Vec<_> = self.port_stats.iter().collect();
        ports.sort_by(|a, b| b.1.cmp(a.1));
        let top_ports: Vec<Value> = ports
            .iter()
            .take(15)
            .map(|(port, pkts)| {
                json!({"port": port, "service": port_to_service(**port), "packets": pkts})
            })
            .collect();

        // Top flows (by bytes, top 20)
        let mut flows: Vec<_> = self.flows.iter().collect();
        flows.sort_by(|a, b| b.1.bytes.cmp(&a.1.bytes));
        let top_flows: Vec<Value> = flows
            .iter()
            .take(20)
            .map(|(k, v)| {
                json!({
                    "src": format!("{}:{}", k.src_ip, k.src_port),
                    "dst": format!("{}:{}", k.dst_ip, k.dst_port),
                    "proto": match k.proto { 6 => "TCP", 17 => "UDP", 1 => "ICMP", 58 => "ICMPv6", _ => "other" },
                    "packets": v.packets,
                    "bytes": v.bytes,
                })
            })
            .collect();

        // DNS queries (top 30 by count)
        let mut dns: Vec<_> = self.dns_queries.iter().collect();
        dns.sort_by(|a, b| b.1.cmp(a.1));
        let dns_queries: Vec<Value> = dns
            .iter()
            .take(30)
            .map(|(key, count)| {
                let parts: Vec<&str> = key.splitn(2, '|').collect();
                json!({"name": parts[0], "type": parts.get(1).unwrap_or(&"?"), "count": count})
            })
            .collect();

        // HTTP requests (top 30 by count)
        let mut http: Vec<_> = self.http_requests.iter().collect();
        http.sort_by(|a, b| b.1.cmp(a.1));
        let http_requests: Vec<Value> = http
            .iter()
            .take(30)
            .map(|(key, count)| {
                let parts: Vec<&str> = key.splitn(3, ' ').collect();
                json!({
                    "method": parts.first().unwrap_or(&"?"),
                    "host": parts.get(1).unwrap_or(&""),
                    "path": parts.get(2).unwrap_or(&"/"),
                    "count": count,
                })
            })
            .collect();

        // Hourly distribution
        let mut hourly_dist: Vec<Value> = Vec::new();
        for h in 0..24u8 {
            if let Some(&count) = self.hourly.get(&h) {
                hourly_dist.push(json!({"hour": format!("{:02}:00", h), "packets": count}));
            }
        }

        // Suspicious (limit 50)
        let suspicious: Vec<Value> = self.suspicious.iter().take(50).cloned().collect();

        // Format timestamps
        let first_ts_str = if self.first_ts != u64::MAX {
            format_timestamp((self.first_ts / 1_000_000_000) as i64)
        } else {
            "N/A".to_string()
        };
        let last_ts_str = if self.last_ts > 0 {
            format_timestamp((self.last_ts / 1_000_000_000) as i64)
        } else {
            "N/A".to_string()
        };

        json!({
            "summary": {
                "file": file_path,
                "total_packets": self.total_packets,
                "total_bytes": self.total_bytes,
                "duration_secs": duration_secs,
                "first_seen": first_ts_str,
                "last_seen": last_ts_str,
                "protocols": {
                    "tcp": self.proto_tcp,
                    "udp": self.proto_udp,
                    "icmp": self.proto_icmp,
                    "other": self.proto_other,
                },
                "ipv4": self.ipv4_count,
                "ipv6": self.ipv6_count,
            },
            "top_talkers": top_talkers,
            "top_ports": top_ports,
            "top_flows": top_flows,
            "dns_queries": dns_queries,
            "http_requests": http_requests,
            "suspicious": suspicious,
            "hourly_distribution": hourly_dist,
        })
    }
}

/// Format Unix timestamp to human-readable string (UTC+8).
fn format_timestamp(secs: i64) -> String {
    match chrono::DateTime::from_timestamp(secs, 0) {
        Some(dt) => {
            let naive = dt.naive_utc() + chrono::Duration::hours(8);
            naive.format("%Y-%m-%d %H:%M:%S (UTC+8)").to_string()
        }
        None => "N/A".to_string(),
    }
}

// ── Tool implementation ─────────────────────────────────────────

pub struct IrPcapAnalyzeTool;

#[async_trait]
impl Tool for IrPcapAnalyzeTool {
    fn name(&self) -> &str {
        "ir_pcap_analyze"
    }

    fn description(&self) -> &str {
        "Analyze a pcap/pcapng capture file for security investigation. \
         Performs protocol distribution, flow tracking, DNS query extraction, \
         HTTP request detection, and suspicious port/pattern identification. \
         Returns structured JSON summary for AI-assisted triage and analysis."
    }

    fn parameters_schema(&self) -> Value {
        json!({
            "type": "object",
            "properties": {
                "file_path": {
                    "type": "string",
                    "description": "Absolute path to the .pcap or .pcapng file to analyze"
                }
            },
            "required": ["file_path"]
        })
    }

    async fn execute(&self, args: Value, _ctx: &ToolContext) -> AgentResult<Value> {
        let file_path = args["file_path"]
            .as_str()
            .ok_or("Missing required parameter: file_path")?;

        tracing::info!("PCAP analysis: {}", file_path);

        let file = File::open(file_path)
            .map_err(|e| format!("Cannot open file '{}': {}", file_path, e))?;
        let mut buf_reader = BufReader::with_capacity(256 * 1024, file);

        let mut pcap_reader = pcap_parser::create_reader(128 * 1024, &mut buf_reader)
            .map_err(|e| format!("Not a valid pcap/pcapng file: {:?}", e))?;

        let mut analysis = PcapAnalysis::new();
        let mut linktype = pcap_parser::Linktype(1); // default: Ethernet
        let mut is_nanosecond = false; // legacy pcap nanosecond precision
        let mut ts_resolution: u64 = 1_000_000; // pcapng: default microsecond
        let mut ts_offset: u64 = 0; // pcapng: interface timestamp offset
        let mut incomplete_count = 0u32;

        loop {
            match pcap_reader.next() {
                Ok((offset, block)) => {
                    incomplete_count = 0;
                    match block {
                        PcapBlockOwned::LegacyHeader(hdr) => {
                            linktype = hdr.network;
                            is_nanosecond = hdr.is_nanosecond_precision();
                        }
                        PcapBlockOwned::Legacy(pkt) => {
                            let ts_ns = if is_nanosecond {
                                pkt.ts_sec as u64 * 1_000_000_000 + pkt.ts_usec as u64
                            } else {
                                pkt.ts_sec as u64 * 1_000_000_000 + pkt.ts_usec as u64 * 1_000
                            };
                            analysis.process_packet(pkt.data, linktype, ts_ns);
                        }
                        PcapBlockOwned::NG(ng_block) => match ng_block {
                            pcap_parser::Block::SectionHeader(_) => {}
                            pcap_parser::Block::InterfaceDescription(idb) => {
                                linktype = idb.linktype;
                                ts_resolution = idb.ts_resolution().unwrap_or(1_000_000);
                                ts_offset = idb.ts_offset().max(0) as u64;
                            }
                            pcap_parser::Block::EnhancedPacket(epb) => {
                                let (ts_sec, ts_frac) = epb.decode_ts(ts_offset, ts_resolution);
                                let ts_ns = ts_sec as u64 * 1_000_000_000
                                    + (ts_frac as u64 * 1_000_000_000) / ts_resolution;
                                analysis.process_packet(epb.packet_data(), linktype, ts_ns);
                            }
                            pcap_parser::Block::SimplePacket(spb) => {
                                analysis.process_packet(spb.packet_data(), linktype, 0);
                            }
                            _ => {}
                        },
                    }
                    pcap_reader.consume_noshift(offset);

                    if analysis.total_packets >= MAX_PACKETS {
                        tracing::info!(
                            "PCAP analysis: reached packet limit ({}), stopping",
                            MAX_PACKETS
                        );
                        break;
                    }
                }
                Err(PcapError::Eof) => break,
                Err(PcapError::Incomplete(_)) => {
                    incomplete_count += 1;
                    if incomplete_count > 3 {
                        tracing::warn!("PCAP analysis: too many incomplete reads, file may be truncated");
                        break;
                    }
                    pcap_reader
                        .refill()
                        .map_err(|e| format!("Pcap refill error: {:?}", e))?;
                }
                Err(e) => {
                    return Err(format!("Pcap read error: {:?}", e).into());
                }
            }
        }

        tracing::info!(
            "PCAP analysis complete: {} packets, {} bytes",
            analysis.total_packets,
            analysis.total_bytes
        );

        Ok(analysis.to_json(file_path))
    }

    fn is_read_only(&self) -> bool {
        true
    }
}

// ── Tests ───────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_ethernet() {
        // Minimal Ethernet frame: dst(6) + src(6) + ethertype(2) + payload
        let mut frame = vec![0u8; 14 + 20];
        frame[12] = 0x08;
        frame[13] = 0x00; // IPv4
        let (ethertype, payload) = parse_ethernet(&frame).unwrap();
        assert_eq!(ethertype, 0x0800);
        assert_eq!(payload.len(), 20);
    }

    #[test]
    fn test_parse_ethernet_vlan() {
        // Ethernet frame with 802.1Q VLAN tag
        let mut frame = vec![0u8; 18 + 20];
        frame[12] = 0x81;
        frame[13] = 0x00; // VLAN tag
        frame[16] = 0x08;
        frame[17] = 0x00; // inner ethertype = IPv4
        let (ethertype, payload) = parse_ethernet(&frame).unwrap();
        assert_eq!(ethertype, 0x0800);
        assert_eq!(payload.len(), 20);
    }

    #[test]
    fn test_parse_ipv4_tcp() {
        // IPv4 header (20 bytes) + TCP header (20 bytes)
        let mut pkt = vec![0u8; 40];
        pkt[0] = 0x45; // version=4, IHL=5
        pkt[2] = 0x00;
        pkt[3] = 40; // total length = 40
        pkt[9] = 6; // TCP
        pkt[12] = 192;
        pkt[13] = 168;
        pkt[14] = 1;
        pkt[15] = 100; // src = 192.168.1.100
        pkt[16] = 10;
        pkt[17] = 0;
        pkt[18] = 0;
        pkt[19] = 1; // dst = 10.0.0.1
        // TCP header
        pkt[20] = 0x04;
        pkt[21] = 0xD2; // src_port = 1234
        pkt[22] = 0x00;
        pkt[23] = 0x50; // dst_port = 80
        pkt[32] = 0x50; // data offset = 5 (20 bytes)

        let info = parse_ipv4(&pkt).unwrap();
        assert_eq!(info.src_ip, "192.168.1.100");
        assert_eq!(info.dst_ip, "10.0.0.1");
        assert_eq!(info.proto, 6);
        assert_eq!(info.src_port, 1234);
        assert_eq!(info.dst_port, 80);
        assert_eq!(info.ip_version, 4);
    }

    #[test]
    fn test_parse_dns_query() {
        // DNS query for "example.com" type A
        let mut dns = vec![0u8; 12];
        dns[2] = 0x01;
        dns[3] = 0x00; // flags: standard query
        dns[5] = 0x01; // QDCOUNT = 1
        // QNAME: 7 "example" 3 "com" 0
        dns.extend_from_slice(&[7]);
        dns.extend_from_slice(b"example");
        dns.extend_from_slice(&[3]);
        dns.extend_from_slice(b"com");
        dns.extend_from_slice(&[0]);
        // QTYPE = A (1), QCLASS = IN (1)
        dns.extend_from_slice(&[0x00, 0x01, 0x00, 0x01]);

        let (name, qtype) = parse_dns_query_name(&dns).unwrap();
        assert_eq!(name, "example.com");
        assert_eq!(qtype, "A");
    }

    #[test]
    fn test_parse_dns_response_skipped() {
        // DNS response (QR=1) should be skipped
        let mut dns = vec![0u8; 12];
        dns[2] = 0x81;
        dns[3] = 0x80; // flags: response
        dns[5] = 0x01;
        assert!(parse_dns_query_name(&dns).is_none());
    }

    #[test]
    fn test_parse_http_request() {
        let http = b"GET /index.html HTTP/1.1\r\nHost: www.example.com\r\nUser-Agent: test\r\n\r\n";
        let (method, host, path) = parse_http_request(http).unwrap();
        assert_eq!(method, "GET");
        assert_eq!(host, "www.example.com");
        assert_eq!(path, "/index.html");
    }

    #[test]
    fn test_parse_http_post() {
        let http = b"POST /api/login HTTP/1.1\r\nHost: api.example.com\r\nContent-Type: application/json\r\n\r\n{}";
        let (method, host, path) = parse_http_request(http).unwrap();
        assert_eq!(method, "POST");
        assert_eq!(host, "api.example.com");
        assert_eq!(path, "/api/login");
    }

    #[test]
    fn test_suspicious_ports() {
        assert!(SUSPICIOUS_PORTS.contains(&4444));
        assert!(SUSPICIOUS_PORTS.contains(&31337));
        assert!(SUSPICIOUS_PORTS.contains(&9050));
        assert!(!SUSPICIOUS_PORTS.contains(&80));
        assert!(!SUSPICIOUS_PORTS.contains(&443));
    }

    #[test]
    fn test_port_to_service() {
        assert_eq!(port_to_service(80), "http");
        assert_eq!(port_to_service(443), "https");
        assert_eq!(port_to_service(3389), "rdp");
        assert_eq!(port_to_service(12345), "unknown");
    }

    #[test]
    fn test_flow_tracking() {
        let mut analysis = PcapAnalysis::new();

        // Build a minimal Ethernet + IPv4 + TCP packet
        let mut frame = vec![0u8; 14 + 20 + 20];
        // Ethernet
        frame[12] = 0x08;
        frame[13] = 0x00;
        // IPv4
        let ip = &mut frame[14..34];
        ip[0] = 0x45;
        ip[2] = 0x00;
        ip[3] = 40;
        ip[9] = 6; // TCP
        ip[12] = 192;
        ip[13] = 168;
        ip[14] = 1;
        ip[15] = 1;
        ip[16] = 10;
        ip[17] = 0;
        ip[18] = 0;
        ip[19] = 1;
        // TCP
        let tcp = &mut frame[34..54];
        tcp[0] = 0x04;
        tcp[1] = 0xD2; // src_port = 1234
        tcp[2] = 0x00;
        tcp[3] = 0x50; // dst_port = 80
        tcp[12] = 0x50; // data offset = 5

        analysis.process_packet(&frame, pcap_parser::Linktype(1), 1_000_000_000);
        analysis.process_packet(&frame, pcap_parser::Linktype(1), 2_000_000_000);

        assert_eq!(analysis.total_packets, 2);
        assert_eq!(analysis.proto_tcp, 2);
        assert_eq!(analysis.flows.len(), 1);

        let key = FlowKey {
            src_ip: "192.168.1.1".to_string(),
            dst_ip: "10.0.0.1".to_string(),
            proto: 6,
            src_port: 1234,
            dst_port: 80,
        };
        assert_eq!(analysis.flows[&key].packets, 2);
    }
}
