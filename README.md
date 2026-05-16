# Efense -- Linux Sensitive Monitor and Protection Tool

*Working in progress, no use at all*

Efense is a Linux tool for security monitor and protection.

## Tools
 * `efensectl` -- command line tool to control `efensed`, including learning and
   applying rules.
 * `efensed` -- background daemon to run eBPF program and collect deny events
   from eBPF kernel program, send the events to `efense-inspector`.
 * `efense-inspector` -- daemon to collect security related events and trigger
   alerts.

## Goals
 * UDP drop/rate-control/redirect
 * TCP SYNC flood protection
 * Sensitive file access control
 * Process behavior(filesystem, socket) monitoring
 * AI based pattern recognition and anomaly detection

## Workflow
 1. The `efensed` start with empty rules and empty `inspector` address,
    nothing will happen. Daemon just wait CLI command.
 2. Invoke `efensectl set-inspector <address>` set `inspector` address.
 3. Invoke `efensectl mode learn` to set `efensed` into learning mode, which
    will collect all security related events(except allowed events) and send to
    `inspector`.
 4. User perform normal production works.
 5. `efense-inspector` daemon will receive the events and analyze them,
    generate rules for legal actions.
 6. `efensectl gen-rules` will request `efense-inspector` to generate rules
    based on the collected events since last learn start time, and output the
    rules in yaml format.
 7. User review the rules, modify if necessary, and apply the rules via
    `efensectl apply` command.
 8. Invoke `efensectl mode enforce` to set `efensed` into enforce mode, which
    will enforce the rules and deny all security related events unless
    explicitly allowed by applied rules.
 9. The denied events will send to `efense-inspector` for further analysis.

## Rule generation

The `efense-inspector` holds many predefined pattern to analyze events and
fallback to AI based pattern recognition and anomaly detection if the events do
not match predefined patterns.

The predefined pattern could be maintained by community after review.

## Configuration

TODO

## License

The code in `src/ebpf` folder are GPL-2.0 only license. Others are Apache 2.0
license.
