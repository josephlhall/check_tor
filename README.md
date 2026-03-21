# Tor Reachability Scanner

A `zsh` utility script for Project Galileo that automates testing a list of domains against a local Tor SOCKS proxy. It verifies whether sites are accessible over the Tor network, checking for WAF blocks, SSL/TLS certificate misconfigurations, and SOCKS connection failures.

## Prerequisites

This script requires macOS and Homebrew to install and run the Tor proxy locally.

1. **Install Tor:**
   ```zsh
   brew install tor
   ```

2. **Set up terminal aliases (Optional but recommended):**
   Add these to your `~/.zshrc` for easy proxy management:
   ```zsh
   alias tor-on='brew services start tor'
   alias tor-off='brew services stop tor'
   alias tor-reset='brew services restart tor'
   ```
   *Run `source ~/.zshrc` to apply the changes.*

## Setup

1. Place `check_tor.zsh` and your target list (e.g., `targets.txt`) in the same directory.
2. Make the script executable:
   ```zsh
   chmod +x check_tor.zsh
   ```

## Usage

1. **Start the Tor proxy:**
   Ensure your local proxy is running on `localhost:9050` before scanning the Internet.
   ```zsh
   tor-on
   ```

2. **Populate your target list:**
   Add the domains you want to test to a text file, one per line. The script will automatically format them to enforce `https://`.
   ```zsh
   emacs targets.txt
   ```

3. **Run the scanner:**
   Pass your text file as an argument to the script.
   ```zsh
   ./check_tor.zsh targets.txt
   ```

4. **Stop the Tor proxy (when finished):**
   ```zsh
   tor-off
   ```

## Output Legend

The script evaluates the `curl` exit codes and HTTP status codes to provide specific diagnostics:

* **[PASS]** (Green): Status 200, 301, 302, or 308. The site is successfully routing Tor traffic over the Internet.
* **[FAIL]** (Red): Status 403, 1020, or 401. The server is actively dropping or blocking the request, likely due to a WAF rule targeting Tor exit nodes.
* **[CERT ERROR]** (Purple): The destination server has an invalid, self-signed, or expired SSL/TLS certificate, terminating the secure connection before an HTTP status can be negotiated.
* **[SOCKS ERROR]** (Red): The Tor circuit was built, but the final exit node could not complete the connection to the host server.
* **[TIMEOUT]** (Yellow): The connection hung and was dropped after 30 seconds. Often caused by silent firewall drops or WAF CAPTCHA loops that block automated requests.

## Generating HTML Documentation

If you prefer to read this documentation in a web browser, you can easily convert this Markdown file to a standalone HTML page using Pandoc.

1. **Install Pandoc (if not already installed):**
   ```zsh
   brew install pandoc
   ```

2. **Convert the README:**
   Run the following command in the same directory as this file:
   ```zsh
   pandoc README.md -f markdown -t html -s -o README.html
   ```
   *You can then open `README.html` directly in your browser.*

## License

This script is marked with CC0 1.0 Universal. 

The person who associated a work with this deed has dedicated the work to the public domain by waiving all of their rights to the work worldwide under copyright law, including all related and neighboring rights, to the extent allowed by law.

You can copy, modify, distribute and perform the work, even for commercial purposes, all without asking permission.

For more information, please refer to <https://creativecommons.org/publicdomain/zero/1.0/>