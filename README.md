# dorkA

Install dependency (one-time):

```bash
pip install duckduckgo-search
```

Person scan:

```bash
python dork_tool.py \
  --target "Jane Doe" \
  --aliases "Jan Doe,J. Doe" \
  --usernames "janedoe99,j_doe" \
  --socials "twitter:janedoe,github:janedoe99" \
  --org "Acme Corp" \
  --location "New York"
```

Organization scan:

```bash
python dork_tool.py --target "Acme Corp" --type organization --org "Acme Corp"
```

Quick scan — specific categories only:

```bash
python dork_tool.py --target "Jane Doe" \
  --categories social_media,email_phone,data_breaches
```

Slow/safe mode (avoids rate-limiting):

```bash
python dork_tool.py --target "Jane Doe" --delay 4.0 --max-total 80
```

Dry-run (print queries without searching):

```bash
python dork_tool.py --target "Jane Doe" --dry-run
```

List all categories:

```bash
python dork_tool.py --list-categories
```
