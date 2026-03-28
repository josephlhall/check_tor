# Tor Reachability Scanner

A `zsh` utility script for Project Galileo that automates testing a list of domains against a local Tor SOCKS proxy. It verifies whether sites are accessible over the Tor network, checking for WAF blocks, SSL/TLS certificate misconfigurations, and SOCKS connection failures. By Joseph Lorenzo Hall, PhD (<https://josephhall.org/>)

## Prerequisites & Installation

This script requires `zsh`, `curl`, and a local `tor` proxy to run.

### For macOS
1. **Install dependencies via Homebrew:**
   ```zsh
   brew install tor
   ```
2. **Set up terminal aliases (Optional but recommended):**
   Add these to your `~/.zshrc` for easy proxy management:
   ```zsh
   alias tor-on='brew services start tor'
   alias tor-off='brew services stop tor'
   alias tor-stat='brew services info tor'
   alias tor-reset='brew services restart tor'
   ```

### For Linux / ChromeOS (Debian/Ubuntu)
1. **Install dependencies via APT:**
   ```zsh
   sudo apt update && sudo apt install zsh tor curl -y
   ```
2. **Set up terminal aliases (Optional but recommended):**
   Add these to your shell profile (e.g., `~/.zshrc`) to map to the system service:
   ```zsh
   alias tor-on='sudo service tor start'
   alias tor-off='sudo service tor stop'
   alias tor-stat='sudo service tor status'
   alias tor-reset='sudo service tor restart'
   ```

*Run `source ~/.zshrc` to apply any alias changes.*

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

* **[PASS]** (Green): Status 200, 301, 302, 307, or 308. The site is successfully routing Tor traffic over the Internet.
* **[CHALLENGE]** (Cyan): Status 202. The Tor connection successfully reached the host, but a Web Application Firewall (WAF) is presenting a JavaScript challenge or holding the request in an asynchronous queue.
* **[FAIL]** (Red): Status 403, 1020, or 401. The server is actively dropping or blocking the request, likely due to a WAF rule targeting Tor exit nodes.
* **[CERT ERROR]** (Purple): The destination server has an invalid, self-signed, or expired SSL/TLS certificate, terminating the secure connection before an HTTP status can be negotiated.
* **[SOCKS ERROR]** (Red): The Tor circuit was built, but the final exit node could not complete the connection to the host server.
* **[TIMEOUT]** (Yellow): The connection hung and was dropped after 60 seconds. Often caused by silent firewall drops or WAF CAPTCHA loops that block automated requests.

## License

This project is dedicated to the public domain under CC0 1.0 Universal. See the `LICENSE` file for details.
