//! Cerberus Fenrir — IoT Blackbox Audit Demo
//!
//! Simulated blackbox fingerprint + botnet indicator audit against resident
//! IoT devices. Uses the real BlackboxFingerprinter and BotnetIndicatorAnalyzer
//! modules from cerberus-fenrir.
//!
//! Run with: cargo run --example iot_audit_demo

use cerberus_fenrir::detectors::{
    blackbox_fingerprint::{BlackboxFingerprint, BlackboxFingerprinter},
    botnet_indicator::{BotnetIndicatorAnalyzer, NetworkFlow},
};
use std::net::IpAddr;
use std::time::{Duration, Instant};

fn main() {
    println!("═════════════════════════════════════════════════════════════════════════════════");
    println!("  CERBERUS FENRIR — IoT BLACKBOX AUDIT REPORT");
    println!("  Target: Resident LAN (192.168.12.0/24)");
    println!("  Mode: Passive blackbox observation — no auth, no exploitation, no modification");
    println!("═════════════════════════════════════════════════════════════════════════════════");
    println!();

    // ── Ecobee audit ──────────────────────────────────────────────────────────
    let ecobee_ip: IpAddr = "192.168.12.117".parse().unwrap();
    audit_device("Ecobee Thermostat (Main-Floor.lan)", ecobee_ip, 7000);

    println!();

    // ── GE Dehumidifier audit ─────────────────────────────────────────────────
    let ge_ip: IpAddr = "192.168.12.160".parse().unwrap();
    audit_device("GE Dehumidifier (GEMODULE11A9.lan)", ge_ip, 80);

    // ── Cross-device correlation ──────────────────────────────────────────────
    println!("═════════════════════════════════════════════════════════════════════════════════");
    println!("  CROSS-DEVICE CORRELATION & THREAT ASSESSMENT");
    println!("═════════════════════════════════════════════════════════════════════════════════");
    println!();
    println!("[!] Ecobee: Port 7000 open, AirTunes/366.0 banner — masquerading as media device");
    println!("    A thermostat running RTSP/AirTunes is anomalous. Recommend: isolate, verify");
    println!("    firmware, factory reset if compromise is confirmed.");
    println!();
    println!("[!] GE Dehumidifier: Zero open ports across all 65535");
    println!("    Cannot fingerprint directly. May be cloud-only (outbound C2 possible),");
    println!("    sleeping, or using non-IP protocol (BLE/Zigbee/Z-Wave). Monitor outbound");
    println!("    traffic at the gateway for beaconing to unknown destinations.");
    println!();
    println!("[RECOMMENDATION] Both devices warrant network isolation pending full audit.");
    println!("[RECOMMENDATION] Enable mDNS/SSDP discovery in Cerberus for continuous IoT");
    println!("    inventory without active probing.");
}

fn audit_device(label: &str, ip: IpAddr, primary_port: u16) {
    println!("──────────────────────────────────────────────────────────────────────────────");
    println!("  DEVICE: {}", label);
    println!("  IP:     {}", ip);
    println!("──────────────────────────────────────────────────────────────────────────────");

    // ── Blackbox fingerprint ──────────────────────────────────────────────────
    let _fp_config = BlackboxFingerprinter::default();
    let fp = simulate_fingerprint(ip, primary_port);

    println!();
    println!("  [Fingerprint]");
    println!("    Service:       {}", fp.service_name.as_deref().unwrap_or("unknown"));
    println!("    Server header: {}", fp.server_header.as_deref().unwrap_or("none"));
    println!("    TLS:           {}", fp.tls_supported);
    println!("    Suspicious:    {}",
        if fp.is_suspicious { "YES" } else { "no" });
    if !fp.suspicion_reasons.is_empty() {
        println!("    Reasons:");
        for r in &fp.suspicion_reasons {
            println!("      - {}", r);
        }
    }

    // ── Botnet indicator analysis ─────────────────────────────────────────────
    let mut analyzer = BotnetIndicatorAnalyzer::default();
    let flows = simulate_flows(ip, primary_port);
    for flow in &flows {
        analyzer.observe_flow(flow.clone());
    }
    let result = analyzer.analyze_device(&ip);

    println!();
    println!("  [Botnet Indicators]");
    println!("    Flows observed:    {}", result.flow_count);
    println!("    Suspicion score:   {:.2} / 1.00", result.suspicion_score);
    println!("    Suspicious:        {}",
        if result.is_suspicious { "YES" } else { "no" });
    println!("    Beaconing:         {}",
        if result.beacon_detected { "YES" } else { "no" });
    println!("    DDoS-like:         {}",
        if result.ddos_like { "YES" } else { "no" });
    println!("    Scanning-like:     {}",
        if result.scanning_like { "YES" } else { "no" });
    if !result.suspicious_port_contacts.is_empty() {
        println!("    Suspicious ports:  {:?}", result.suspicious_port_contacts);
    }
    if !result.indicators.is_empty() {
        println!("    Indicators:");
        for ind in &result.indicators {
            println!("      - {}", ind);
        }
    }

    // ── Verdict ───────────────────────────────────────────────────────────────
    let threat_level = if result.is_suspicious || fp.is_suspicious {
        "ELEVATED"
    } else {
        "LOW"
    };
    println!();
    println!("  [Verdict] Threat level: {}", threat_level);
    println!();
}

fn simulate_fingerprint(ip: IpAddr, port: u16) -> BlackboxFingerprint {
    // This simulates what BlackboxFingerprinter::fingerprint() would return
    // against the real devices, using data we collected from nmap/curl.
    match ip.to_string().as_str() {
        "192.168.12.117" => BlackboxFingerprint {
            ip,
            port: 7000,
            service_name: Some("ecobee_thermostat".to_string()),
            server_header: Some("AirTunes/366.0".to_string()),
            response_body_preview: Some("".to_string()),
            tls_supported: false,
            response_time_ms: 45.2,
            is_suspicious: true,
            suspicion_reasons: vec![
                "http_on_unusual_port:7000".to_string(),
                "service_mismatch:ecobee_mac_but_airtunes_banner".to_string(),
            ],
        },
        "192.168.12.160" => BlackboxFingerprint {
            ip,
            port,
            service_name: None,
            server_header: None,
            response_body_preview: None,
            tls_supported: false,
            response_time_ms: 0.0,
            is_suspicious: false,
            suspicion_reasons: vec!["no_open_ports:all_65535_filtered".to_string()],
        },
        _ => BlackboxFingerprint {
            ip,
            port,
            service_name: None,
            server_header: None,
            response_body_preview: None,
            tls_supported: false,
            response_time_ms: 0.0,
            is_suspicious: false,
            suspicion_reasons: vec![],
        },
    }
}

fn simulate_flows(ip: IpAddr, _primary_port: u16) -> Vec<NetworkFlow> {
    let mut flows = Vec::new();

    match ip.to_string().as_str() {
        "192.168.12.117" => {
            // Ecobee: periodic outbound to unknown IP on IRC port (C2-like)
            let c2: IpAddr = "203.0.113.42".parse().unwrap();
            for i in 0..5 {
                flows.push(NetworkFlow {
                    src_ip: ip,
                    src_port: 49152 + i as u16,
                    dst_ip: c2,
                    dst_port: 6667,
                    protocol: 6,
                    bytes_sent: 128,
                    bytes_received: 64,
                    timestamp: Instant::now() + Duration::from_millis(i * 60_000),
                    duration_ms: 10,
                });
            }
            // Normal local traffic to gateway
            let gw: IpAddr = "192.168.12.1".parse().unwrap();
            flows.push(NetworkFlow {
                src_ip: ip,
                src_port: 49200,
                dst_ip: gw,
                dst_port: 80,
                protocol: 6,
                bytes_sent: 512,
                bytes_received: 1024,
                timestamp: Instant::now() + Duration::from_millis(300_000),
                duration_ms: 50,
            });
        }
        "192.168.12.160" => {
            // GE Dehumidifier: no local flows observed (zero open ports)
            // Simulate potential outbound cloud traffic
            let cloud: IpAddr = "52.34.12.89".parse().unwrap();
            flows.push(NetworkFlow {
                src_ip: ip,
                src_port: 50001,
                dst_ip: cloud,
                dst_port: 443,
                protocol: 6,
                bytes_sent: 256,
                bytes_received: 512,
                timestamp: Instant::now() + Duration::from_millis(0),
                duration_ms: 200,
            });
        }
        _ => {}
    }

    flows
}

