# System Safety Checker

A lightweight Rust tool that performs comprehensive system and network safety checks. The program runs automatically on system startup and helps identify potential security issues and system health problems.

## Features

- System resource monitoring (CPU, Memory, Disk usage)
- Network connection analysis
- Suspicious process detection
- Firewall status verification
- Cross-platform support (Windows and Linux)

## Requirements

- Rust 1.56 or later
- Windows or Linux operating system
- Administrator/root privileges for some checks

## Installation

1. Clone the repository
2. Build the project:
```bash
cargo build --release
```

## Usage

The program can be run directly:
```bash
cargo run --release
```

To set up automatic startup:

### Windows
1. Create a shortcut to the executable
2. Press Win + R, type `shell:startup`
3. Copy the shortcut to the Startup folder

### Linux
1. Create a systemd service file:
```bash
sudo nano /etc/systemd/system/safety-checker.service
```

2. Add the following content:
```ini
[Unit]
Description=System Safety Checker
After=network.target

[Service]
Type=simple
ExecStart=/path/to/safety-checker
Restart=always

[Install]
WantedBy=multi-user.target
```

3. Enable and start the service:
```bash
sudo systemctl enable safety-checker
sudo systemctl start safety-checker
```

## Logging

The program uses the `log` crate for logging. To see the output, set the `RUST_LOG` environment variable:

```bash
# Windows
set RUST_LOG=info

# Linux
export RUST_LOG=info
```

## Security Considerations

- The program requires elevated privileges to perform some checks
- All checks are performed locally and no data is sent to external servers
- The program only logs warnings and errors, no sensitive information is stored

## License

MIT License
