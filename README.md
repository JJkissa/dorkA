### JAJAJAJA

# Install dependency (one-time)
pip install duckduckgo-search

# Person scan
python dork_tool.py \
  --target "Jane Doe" \
  --aliases "Jan Doe,J. Doe" \
  --usernames "janedoe99,j_doe" \
  --socials "twitter:janedoe,github:janedoe99" \
  --org "Acme Corp" \
  --location "New York"

# Organisation scan
python dork_tool.py --target "Acme Corp" --type organization --org "Acme Corp"

# Quick scan — specific categories only
python dork_tool.py --target "Jane Doe" \
  --categories social_media,email_phone,data_breaches

# Slow/safe mode (avoids rate-limiting)
python dork_tool.py --target "Jane Doe" --delay 4.0 --max-total 80

# Dry-run (print queries without searching)
python dork_tool.py --target "Jane Doe" --dry-run

# List all categories
python dork_tool.py --list-categories
