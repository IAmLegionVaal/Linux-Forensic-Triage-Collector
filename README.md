# Linux Forensic Triage Collector

A Linux incident-response toolkit for collecting structured evidence and applying selected, authorised containment actions after evidence capture.

## Evidence collection

```bash
chmod +x src/linux_forensic_triage.sh
sudo ./src/linux_forensic_triage.sh --hours 48 --output /secure/cases/host-01
```

## Guarded response workflow

```bash
chmod +x src/linux_forensic_response.sh
sudo ./src/linux_forensic_response.sh --stop-service suspicious.service --dry-run
```

Supported response actions:

```bash
sudo ./src/linux_forensic_response.sh --stop-service suspicious.service
sudo ./src/linux_forensic_response.sh --terminate-pid 1234
sudo ./src/linux_forensic_response.sh --quarantine-file /path/to/suspicious-file
```

## What the response workflow does

- Captures process, network, service, journal and target-specific evidence first.
- Creates SHA-256 evidence manifests.
- Stops one selected systemd service.
- Terminates one selected non-system user process with a normal TERM request.
- Hashes and copies one selected regular file into a protected quarantine directory before removing the original.
- Refuses symlink quarantine targets and low/system PIDs.
- Supports dry-run, confirmation prompts, logs and clear exit codes.

## Safety and evidence handling

Use only on systems you own or are authorised to investigate. Containment changes can affect evidence and production services, so follow your organisation’s incident-response and chain-of-custody procedures. The original collector remains non-destructive; response actions are separate and explicit.

## Author

Dewald Pretorius — L2 IT Support Engineer
