# Zoraxy Guard

Monitors [Zoraxy](https://github.com/tobychui/zoraxy) reverse-proxy logs for:

- exploit / scanner paths (`.env`, `wp-admin`, …)
- known malicious IPs from **public threat databases** and **your own lists**
- bad user-agents
- block storms and brute-force patterns
- optional successful access to sensitive hosts

Alerts via **Discord**, **Telegram**, generic webhook, and container logs.

Image (after CI is enabled): `ghcr.io/paulg67/zoraxy-guard:latest`

Until the GHCR image is published, build from this repo on Unraid (see below).

## Unraid install (Docker Compose Manager)

1. Create folders:
   ```bash
   mkdir -p /mnt/user/appdata/zoraxy-guard/data/lists
   mkdir -p /mnt/user/appdata/zoraxy-guard/data/feed-cache
   cd /mnt/user/appdata
   git clone https://github.com/PaulG67/zoraxy-guard.git zoraxy-guard-src
   curl -fsSL https://raw.githubusercontent.com/PaulG67/zoraxy-guard/main/config.example.yaml \
     -o /mnt/user/appdata/zoraxy-guard/config.yaml
   ```
2. Edit `config.yaml` (domains under `sensitive_hosts`, Discord webhook optional).
3. Stack / compose (build from GitHub, then later switch to GHCR image):
   ```yaml
   services:
     zoraxy-guard:
       build: https://github.com/PaulG67/zoraxy-guard.git#main
       # image: ghcr.io/paulg67/zoraxy-guard:latest
       container_name: zoraxy-guard
       restart: unless-stopped
       environment:
         TZ: Europe/Zurich
         DISCORD_WEBHOOK: "https://discord.com/api/webhooks/..."
         KNOWN_LISTS: "ipsum-level5,blocklist-de-apache,blocklist-de-bruteforce,feodo-ip"
         ALLOWLIST_IPS: "192.168.0.0/16,10.0.0.0/8"
       volumes:
         - /mnt/user/appdata/zoraxy/log:/logs:ro
         - /mnt/user/appdata/zoraxy-guard/config.yaml:/config/config.yaml:ro
         - /mnt/user/appdata/zoraxy-guard/data:/data
   ```
4. Adjust the **Zoraxy log path** if yours differs.
5. Start the stack. Check logs: `docker logs -f zoraxy-guard`

### Publish prebuilt image (optional)

The GitHub Actions workflow lives at [`devtools/docker-publish.yml`](devtools/docker-publish.yml). To enable automatic GHCR builds:

```bash
gh auth refresh -h github.com -s workflow
mkdir -p .github/workflows
mv devtools/docker-publish.yml .github/workflows/
git add .github/workflows/docker-publish.yml
git commit -m "Enable GHCR publish workflow"
git push
```

Then make the package **public**: GitHub → Packages → zoraxy-guard → Package settings → Change visibility.


## Threat lists / databases

### Built-in catalog (`known_lists`)

Enable by name in `config.yaml` or env `KNOWN_LISTS=a,b,c`:

| Name | Source |
|---|---|
| `ipsum-level3` / `level4` / `level5` | [IPsum](https://github.com/stamparm/ipsum) |
| `spamhaus-drop` / `edrop` / `dropv6` | Spamhaus DROP |
| `blocklist-de-all` / `ssh` / `apache` / `bruteforce` | blocklist.de |
| `cinsscore-ci-badguys` | CINS Army |
| `greensnow` | GreenSnow |
| `tor-exit-nodes` | Tor exit list (noisy) |
| `firehol-level1` / `level2` | FireHOL ipsets |
| `feodo-ip` | abuse.ch Feodo |
| `sslbl-ip` | abuse.ch SSLBL CSV |

### Local list folder (`lists_dir`)

Drop files into `/data/lists` (on Unraid: `appdata/zoraxy-guard/data/lists/`):

| File name pattern | Meaning |
|---|---|
| `*.txt`, `*.list`, `*.netset`, `*.ipset` | IP / CIDR per line |
| `*.csv` | abuse.ch-style CSV |
| `*useragent*` / `*_ua.txt` | User-Agent fragments |
| `*path*` / `*exploit*` | Exploit path patterns |

### Custom remote lists

```yaml
custom_lists:
  - name: team-block
    url: https://example.com/bad-ips.txt
    format: plain_ip   # plain_ip | spamhaus | abusech_csv
    kind: ip           # ip | user_agent | path
    enabled: true
```

Lists are cached under `/data/feed-cache` and refreshed every `lists_refresh_hours` (default 24).

## Alerting

```yaml
alerts:
  min_severity: medium
  discord_webhook: "https://discord.com/api/webhooks/..."
  # or env DISCORD_WEBHOOK

  pushover:
    user_key: "u..."       # or env PUSHOVER_USER_KEY
    api_token: "a..."      # or env PUSHOVER_API_TOKEN
    device: ""             # optional
    sound: "pushover"      # optional
```

| Channel | Config / Env |
|---|---|
| Discord | `discord_webhook` / `DISCORD_WEBHOOK` |
| Telegram | `TELEGRAM_BOT_TOKEN` + `TELEGRAM_CHAT_ID` |
| **Pushover** | `PUSHOVER_USER_KEY` + `PUSHOVER_API_TOKEN` (+ optional `PUSHOVER_DEVICE`, `PUSHOVER_SOUND`) |
| Generic webhook | `GENERIC_WEBHOOK` |

Pushover priorities (default): `info/low=-1`, `medium=0`, `high=1`, `critical=2` (emergency with retry/expire).

Create an app at [pushover.net/apps/build](https://pushover.net/apps/build), copy **API Token** and your **User Key** from the dashboard.

## Config tips

- Always allowlist LAN (`192.168.x.0/16`) so family devices are quiet.
- Start with `ipsum-level5` + `blocklist-de-apache` (less noise than level3).
- `alert_sensitive_success: false` avoids alerts when you open Admin apps via mobile data.

## License

MIT
