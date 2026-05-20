### JAJAJAJA

# Install dependency (one-time)(ajaa itekin)((hups, aja venvissä ni ei hajoo mikää)):D
pip install ddgs

# Person scan
python dork_tool.py
  --target "Jane Doe"
  --aliases "Jan Doe,J. Doe"
  --usernames "janedoe99,j_doe"
  --socials "twitter:janedoe,github:janedoe99"
  --org "Acme Corp" 
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


# Usage
Basic Execution (With LLM Enabled)
By default, the tool will attempt to connect to localhost:1234 to generate dynamic queries based on the target context, execute them, and validate the results.

# Bash
python3 dork_tool.py \\
  --target "John Doe" \\
  --location "Helsinki, Finland" \\
  --org "CyberCorp" \\
  --socials "github:johndoe99,linkedin:john-doe" \\
  --llm-gen-timeout 5
Execution (LLM Disabled)
If your LLM is offline or you want to run a quick, static search using the internal dork database:

# Bash
python3 dork_tool.py \\
  --target "John Doe" \\
  --disable-llm \\
  --categories "documents,data_breaches"
# Command-Line Arguments
Target Context (Used by LLM & Static DB)
--target (Required): Target's full name or company name.

--aliases: Comma-separated known aliases (e.g., jdoe,johnny).

--usernames: Comma-separated known usernames.

--socials: Comma-separated platform/handle pairs (e.g., twitter:jdoe,github:jdoe).

--org: Known associated organization or employer.

--location: Target's geographic location.

# Execution Control
--categories: Comma-separated list of static dork categories to run (e.g., documents,social_media,data_breaches).

--max-per-query: Maximum number of search results to process per dork query (Default: 5).

--delay: Time delay (in seconds) between queries to prevent rate-limiting (Default: 2.0).

--max-total: Hard cap on the total number of queries to execute.

--output: Custom file path for the HTML report.

# LLM Architecture Configuration
--llm-url: Base URL for the OpenAPI local LLM (Default: http://localhost:1234/v1).

--llm-model: The specific model identifier to pass in the payload (Default: llama-3.2).

--llm-gen-timeout: Maximum time budget in minutes to spend generating contextual queries (Default: 10).

--disable-llm: Flag to bypass all LLM generation and validation logic entirely.

# Outputs
HTML Report (osint_targetname_timestamp.html): A styled, standalone dashboard containing validated links, categorized by risk, with context snippets.

Generated Dorks Cache (llm_dorks_targetname_timestamp.json): If the LLM successfully generates contextual dorks, they are saved locally so you can review the AI's OSINT strategy or reuse them later.
""")
