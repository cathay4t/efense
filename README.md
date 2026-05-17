# Efense -- Linux Sensitive Monitor and Protection Tool

*Working in progress, no use at all*

Efense is a Linux tool for security monitor and protection.

## Goals
 * UDP drop/rate-control/redirect
 * TCP SYNC flood protection
 * Sensitive file access control
 * Process behavior(filesystem, socket) monitoring
 * AI based pattern recognition and anomaly detection

## Usage

### Query loaded rules

```
efctl show
```

### Monitor

```
efctl monitor
```

### Generate rules for legal events

```
efctl gen-allow <event_dump_file>
```

### Inspect security breaches

```
efctl inspect <event_dump_file>
```

### Apply config

```
efctl apply <config_file>
```

## License

The code in `src/ebpf` folder are GPL-2.0 only license. Others are Apache 2.0
license.
