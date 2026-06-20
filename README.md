# Linux Forensic Triage Collector

A read-only Bash toolkit for collecting volatile and high-value Linux incident-response evidence in a structured, timestamped case directory.

## Intended use

Use this project only on systems you own or are authorised to investigate. It is designed for defensive triage, escalation evidence, and lab exercises—not covert monitoring.

## Evidence collected

- Host, OS, kernel, time, boot, and hardware context
- Logged-on users, login history, failed logins, and account inventory
- Running processes, parent-child relationships, loaded executables, and process hashes where readable
- Listening and established network connections
- Routes, neighbours, DNS configuration, and interface state
- Enabled services, failed units, timers, cron metadata, and startup persistence locations
- Loaded kernel modules
- Recent authentication, sudo, kernel, and high-priority journal events
- Recently modified executable files in common system paths
- Package verification information when supported
- SHA-256 manifest for all generated evidence files

## Usage

```bash
chmod +x src/linux_forensic_triage.sh
sudo ./src/linux_forensic_triage.sh
```

```bash
sudo ./src/linux_forensic_triage.sh --hours 48 --output /secure/cases/host-01
```

## Safety and evidence handling

The collector does not kill processes, block connections, quarantine files, alter timestamps, change permissions, or remediate findings. Run from trusted media when possible, record the command used, preserve output securely, and follow your organisation's chain-of-custody process.

## Privacy

The output may contain usernames, internal IP addresses, process arguments, hostnames, paths, login history, and security events. Treat it as sensitive evidence.

## Requirements

- Bash 4+
- Root privileges for complete evidence
- Optional tools such as `lsof`, `rpm`, `dpkg`, `ausearch`, and `sha256sum`

## Author

Dewald Pretorius — L2 IT Support Engineer
