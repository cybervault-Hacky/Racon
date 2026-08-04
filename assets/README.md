# Assets

Store non-code assets here:

- `logo.png` — project logo / banner
- `screenshots/` — terminal UI and report screenshots (for documentation)
- `favicon/` — web report favicon

## Generating documentation screenshots

Run RACON against an authorized target in an interactive terminal and capture
the output, for example:

```bash
python racon.py -t example.com --modules basic_info,dns_intelligence
```

Then open the generated HTML report in a browser and capture screenshots of
the executive summary, findings, and module tables. Save them under
`assets/screenshots/` and reference them from the README.
