# Usage Guide

RACON is invoked from the command line. Run `python racon.py --help` for the
full option reference.

## Command-Line Options

| Option | Description |
|--------|-------------|
| `-t, --target` | Target hostname or IP address (may include `scheme://` and `:port`) |
| `-c, --config` | Path to a custom YAML configuration file |
| `-f, --format` | Report format(s): `html`, `json`, `csv`, `pdf`, or `all` |
| `--threads` | Override worker thread count |
| `--timeout` | Override HTTP request timeout (seconds) |
| `--output` | Override the output directory |
| `--modules` | Comma-separated module keys to run |
| `-v, --verbose` | Enable DEBUG logging |
| `-q, --quiet` | Suppress the banner (headless) |
| `--command` | Open interactive command mode |
| `--version` | Print version and exit |

## Common Workflows

### Full assessment

```bash
python racon.py -t example.com -f all
```

Runs all enabled modules and produces HTML, JSON, CSV, and PDF reports.

### Assessment of an internal IP on a non-standard port

```bash
python racon.py -t http://192.168.1.20:8443 --modules basic_info,web_enumeration
```

### Targeted DNS / SSL reconnaissance

```bash
python racon.py -t example.com --modules dns_intelligence,ssl_analysis -f json
```

### Adjusting scan aggressiveness

```bash
python racon.py -t example.com --threads 32 --timeout 8 -v
```

## Interactive Command Mode

Launch with a target to combine a live dashboard with a command prompt, or
use `--command` for a standalone menu:

```bash
python racon.py --command
```

Available commands:

| Command | Description |
|---------|-------------|
| `help` | Show all commands |
| `modules` | List available modules |
| `status` | Show scan status |
| `abort` | Abort the current scan |
| `exit` | Exit RACON |

## Output Layout

```
output/
├── reports/
│   ├── example.com_report.html
│   ├── example.com_report.json
│   ├── example.com_report.csv
│   └── example.com_report.pdf
├── logs/
│   └── racon.log
└── scans/
    └── history.jsonl        # scan history metadata
```

## Keyboard Handling

- Press `Ctrl+C` during a scan to gracefully abort. RACON records the scan as
  `aborted` in history and returns a clean exit code.
- The interactive command mode accepts typed commands as well as single-word
  shortcuts.
