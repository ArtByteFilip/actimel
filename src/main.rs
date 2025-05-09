use chrono::Local;
use log::{info, warn, error};
use netstat2::{get_sockets_info, AddressFamilyFlags, ProtocolFlags};
use std::process::Command;
use sysinfo::{System, SystemExt, ProcessExt, DiskExt, CpuExt, NetworkExt};
use std::collections::HashMap;

struct SafetyCheck {
    timestamp: String,
    system_info: System,
    security_score: i32,
}

impl SafetyCheck {
    fn new() -> Self {
        SafetyCheck {
            timestamp: Local::now().format("%Y-%m-%d %H:%M:%S").to_string(),
            system_info: System::new_all(),
            security_score: 100,
        }
    }

    fn check_system_resources(&mut self) {
        println!("\n=== System Resources Check ===");
        self.system_info.refresh_all();
        
        // Check CPU usage
        let cpu_usage = self.system_info.global_cpu_info().cpu_usage();
        println!("CPU Usage: {:.1}%", cpu_usage);
        if cpu_usage > 90.0 {
            warn!("High CPU usage detected: {:.1}%", cpu_usage);
            self.security_score -= 5;
        }

        // Check memory usage
        let total_memory = self.system_info.total_memory();
        let used_memory = self.system_info.used_memory();
        let memory_usage_percent = (used_memory as f32 / total_memory as f32) * 100.0;
        println!("Memory Usage: {:.1}%", memory_usage_percent);
        if memory_usage_percent > 85.0 {
            warn!("High memory usage detected: {:.1}%", memory_usage_percent);
            self.security_score -= 5;
        }

        // Check disk space
        println!("\nDisk Space Analysis:");
        for disk in self.system_info.disks() {
            let total_space = disk.total_space();
            let available_space = disk.available_space();
            let used_percent = ((total_space - available_space) as f32 / total_space as f32) * 100.0;
            println!("Drive {}: {:.1}% used ({:.1} GB free)", 
                disk.mount_point().to_string_lossy(), 
                used_percent,
                available_space as f64 / 1_000_000_000.0);
            if used_percent > 90.0 {
                warn!("Low disk space on {}: {:.1}% used", disk.mount_point().to_string_lossy(), used_percent);
                self.security_score -= 5;
            }
        }
    }

    fn check_network_connections(&mut self) {
        println!("\n=== Network Security Analysis ===");
        self.system_info.refresh_networks();
        
        // Check network interfaces
        println!("\nNetwork Interfaces:");
        for (interface_name, network) in self.system_info.networks() {
            println!("Interface: {}", interface_name);
            println!("  Received: {:.2} MB", network.received() as f64 / 1_000_000.0);
            println!("  Transmitted: {:.2} MB", network.transmitted() as f64 / 1_000_000.0);
        }

        // Check active connections
        match get_sockets_info(AddressFamilyFlags::IPV4 | AddressFamilyFlags::IPV6, ProtocolFlags::TCP | ProtocolFlags::UDP) {
            Ok(sockets) => {
                let mut suspicious_ports = Vec::new();
                let mut total_connections = 0;
                
                for socket in sockets {
                    total_connections += 1;
                    let port = socket.local_port();
                    
                    // Check for common suspicious ports
                    if port < 1024 && port != 80 && port != 443 {
                        suspicious_ports.push(port);
                    }
                }

                println!("\nConnection Statistics:");
                println!("Total active connections: {}", total_connections);

                if !suspicious_ports.is_empty() {
                    warn!("Suspicious ports detected:");
                    for port in suspicious_ports {
                        println!("  - Port {}", port);
                    }
                    self.security_score -= 10;
                } else {
                    println!("No suspicious ports detected");
                }
            }
            Err(e) => error!("Failed to get network connections: {}", e),
        }
    }

    fn check_running_processes(&mut self) {
        println!("\n=== Process Security Analysis ===");
        self.system_info.refresh_processes();
        
        let suspicious_processes = [
            "netcat", "nc", "telnet", "rsh", "rlogin", "rexec",
            "wireshark", "tcpdump", "nmap", "metasploit", "cain",
            "john", "hashcat", "aircrack", "kismet", "ettercap"
        ];

        let mut found_suspicious = false;
        let mut high_cpu_processes = Vec::new();
        let mut high_memory_processes = Vec::new();

        for (pid, process) in self.system_info.processes() {
            let name = process.name().to_lowercase();
            
            // Check for suspicious processes
            if suspicious_processes.iter().any(|&p| name.contains(p)) {
                warn!("Suspicious process detected: {} (PID: {})", name, pid);
                found_suspicious = true;
                self.security_score -= 15;
            }

            // Check for high resource usage
            if process.cpu_usage() > 50.0 {
                high_cpu_processes.push((name.clone(), process.cpu_usage()));
            }
            if process.memory() > 500_000_000 { // 500MB
                high_memory_processes.push((name.clone(), process.memory() as f64 / 1_000_000.0));
            }
        }

        if !found_suspicious {
            println!("No suspicious processes detected");
        }

        if !high_cpu_processes.is_empty() {
            println!("\nHigh CPU Usage Processes:");
            for (name, usage) in high_cpu_processes {
                println!("  - {}: {:.1}%", name, usage);
            }
        }

        if !high_memory_processes.is_empty() {
            println!("\nHigh Memory Usage Processes:");
            for (name, usage) in high_memory_processes {
                println!("  - {}: {:.1} MB", name, usage);
            }
        }
    }

    fn check_security_software(&mut self) {
        println!("\n=== Security Software Check ===");
        
        #[cfg(target_os = "windows")]
        {
            // Check Windows Defender
            let output = Command::new("powershell")
                .args(["Get-MpComputerStatus"])
                .output();

            match output {
                Ok(output) => {
                    let status = String::from_utf8_lossy(&output.stdout);
                    println!("Windows Defender Status:");
                    println!("{}", status);
                    if !status.contains("True") {
                        warn!("Windows Defender might not be fully enabled");
                        self.security_score -= 20;
                    }
                }
                Err(e) => error!("Failed to check Windows Defender status: {}", e),
            }
        }

        #[cfg(target_os = "linux")]
        {
            // Check common Linux security tools
            let security_tools = ["clamav", "ufw", "fail2ban", "apparmor"];
            for tool in security_tools {
                let output = Command::new("which")
                    .arg(tool)
                    .output();
                
                match output {
                    Ok(output) => {
                        if output.status.success() {
                            println!("{} is installed", tool);
                        } else {
                            warn!("{} is not installed", tool);
                            self.security_score -= 5;
                        }
                    }
                    Err(_) => {
                        warn!("{} is not installed", tool);
                        self.security_score -= 5;
                    }
                }
            }
        }
    }

    fn check_system_updates(&mut self) {
        println!("\n=== System Update Status ===");
        
        #[cfg(target_os = "windows")]
        {
            let output = Command::new("powershell")
                .args(["Get-HotFix", "-Id", "KB*", "|", "Sort-Object", "-Property", "InstalledOn", "-Descending", "|", "Select-Object", "-First", "1"])
                .output();

            match output {
                Ok(output) => {
                    let status = String::from_utf8_lossy(&output.stdout);
                    println!("Last Windows Update:");
                    println!("{}", status);
                }
                Err(e) => error!("Failed to check Windows updates: {}", e),
            }
        }

        #[cfg(target_os = "linux")]
        {
            let output = Command::new("apt-get")
                .args(["update", "-y"])
                .output();

            match output {
                Ok(_) => {
                    let output = Command::new("apt-get")
                        .args(["upgrade", "-s"])
                        .output();

                    match output {
                        Ok(output) => {
                            let status = String::from_utf8_lossy(&output.stdout);
                            println!("Available Updates:");
                            println!("{}", status);
                        }
                        Err(e) => error!("Failed to check available updates: {}", e),
                    }
                }
                Err(e) => error!("Failed to update package list: {}", e),
            }
        }
    }

    fn check_firewall_status(&mut self) {
        println!("\n=== Firewall Status ===");
        #[cfg(target_os = "windows")]
        {
            let output = Command::new("netsh")
                .args(["advfirewall", "show", "allprofiles", "state"])
                .output();

            match output {
                Ok(output) => {
                    let status = String::from_utf8_lossy(&output.stdout);
                    println!("Windows Firewall Status:");
                    println!("{}", status);
                    if !status.contains("ON") {
                        warn!("Firewall might not be fully enabled");
                        self.security_score -= 15;
                    }
                }
                Err(e) => error!("Failed to check firewall status: {}", e),
            }
        }

        #[cfg(target_os = "linux")]
        {
            let output = Command::new("ufw")
                .arg("status")
                .output();

            match output {
                Ok(output) => {
                    let status = String::from_utf8_lossy(&output.stdout);
                    println!("Linux Firewall Status:");
                    println!("{}", status);
                    if !status.contains("active") {
                        warn!("Firewall might not be fully enabled");
                        self.security_score -= 15;
                    }
                }
                Err(e) => error!("Failed to check firewall status: {}", e),
            }
        }
    }

    fn run_all_checks(&mut self) {
        println!("=== System Safety Checker Starting ===");
        println!("Time: {}", self.timestamp);
        println!("----------------------------------------");
        
        self.check_system_resources();
        self.check_network_connections();
        self.check_running_processes();
        self.check_security_software();
        self.check_system_updates();
        self.check_firewall_status();
        
        println!("\n=== Security Score ===");
        println!("Overall Security Score: {}/100", self.security_score);
        if self.security_score < 70 {
            warn!("System security needs attention!");
        } else if self.security_score < 90 {
            warn!("System security could be improved");
        } else {
            println!("System security is in good condition");
        }
        
        println!("----------------------------------------");
        println!("=== System Safety Checker Completed ===");
    }
}

fn main() {
    // Initialize logger with console output
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("info"))
        .format_timestamp(None)
        .format_module_path(false)
        .init();
    
    let mut safety_check = SafetyCheck::new();
    safety_check.run_all_checks();
}