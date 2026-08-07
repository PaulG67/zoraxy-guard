# Zoraxy Guard

Monitors [Zoraxy](https://github.com/tobychui/zoraxy) reverse-proxy logs for exploits, threat-list IPs, bad user-agents, and auth anomalies.

**Web GUI:** port **8787** · Alerts: Discord, Telegram, Pushover, webhook

Image tag: `ghcr.io/paulg67/zoraxy-guard:latest` (auto-build via GitHub Actions on push to `main`)

**Unraid updates:** Docker → zoraxy-guard → **Force update** (pull latest). No reinstall script needed once the image is published.

## Unraid – Vorlage (Docker → Container hinzufügen)

### Einmal im Terminal

```bash
bash <(curl -fsSL https://raw.githubusercontent.com/PaulG67/zoraxy-guard/main/unraid/install-template.sh)
```

Das Script:

1. legt `appdata/zoraxy-guard` + `config.yaml` an  
2. installiert die User-Vorlage nach  
   `/boot/config/plugins/dockerMan/templates-user/my-zoraxy-guard.xml`  
3. **baut das Docker-Image lokal** (damit „Container hinzufügen“ ohne GHCR-Login funktioniert)

### Dann in der WebUI

1. **Docker → Container hinzufügen**  
2. **Template** → **zoraxy-guard** wählen  
3. Zoraxy-**Log-Pfad** prüfen (`…/zoraxy/log` mit `zr_*.log`)  
4. Optional: `WEB_PASSWORD`, Pushover, Discord  
5. **Apply**  
6. GUI: `http://UNRAID-IP:8787`

Updates: Script erneut ausführen (neues Image), Container neu erstellen/starten.

### Manuell ohne Script

```bash
mkdir -p /mnt/user/appdata/zoraxy-guard/data/{lists,feed-cache} \
  /boot/config/plugins/dockerMan/templates-user

curl -fsSL https://raw.githubusercontent.com/PaulG67/zoraxy-guard/main/config.example.yaml \
  -o /mnt/user/appdata/zoraxy-guard/config.yaml

curl -fsSL https://raw.githubusercontent.com/PaulG67/zoraxy-guard/main/unraid/my-zoraxy-guard.xml \
  -o /boot/config/plugins/dockerMan/templates-user/my-zoraxy-guard.xml

git clone --depth 1 https://github.com/PaulG67/zoraxy-guard.git /mnt/user/appdata/zoraxy-guard-src
docker build -t ghcr.io/paulg67/zoraxy-guard:latest /mnt/user/appdata/zoraxy-guard-src
```

## Web UI

| Seite | Funktion |
|---|---|
| Status | Zähler, Alarme, Test-Alert, Listen neu laden |
| Konfiguration | Formular + YAML |
| Listen | lokale Dateien + Katalog |

`config.yaml` muss im Template **schreibbar** gemountet sein (GUI speichert dorthin).

## Docker Compose (Alternative)

```yaml
services:
  zoraxy-guard:
    build: https://github.com/PaulG67/zoraxy-guard.git#main
    image: ghcr.io/paulg67/zoraxy-guard:latest
    container_name: zoraxy-guard
    restart: unless-stopped
    ports:
      - "8787:8787"
    environment:
      TZ: Europe/Zurich
      WEB_PASSWORD: "change-me"
    volumes:
      - /mnt/user/appdata/zoraxy/log:/logs:ro
      - /mnt/user/appdata/zoraxy-guard/config.yaml:/config/config.yaml
      - /mnt/user/appdata/zoraxy-guard/data:/data
```

## Threat lists

| Name | Source |
|---|---|
| `ipsum-level3` / `4` / `5` | IPsum |
| `spamhaus-drop` / `edrop` / `dropv6` | Spamhaus |
| `blocklist-de-all` / `ssh` / `apache` / `bruteforce` | blocklist.de |
| `cinsscore-ci-badguys` | CINS |
| `greensnow` | GreenSnow |
| `feodo-ip` / `sslbl-ip` | abuse.ch |
| `firehol-level1` / `2` | FireHOL |
| `tor-exit-nodes` | Tor (laut) |

Local files: `/data/lists/` · also `custom_lists` URLs in config.

## Alerting

Env: `DISCORD_WEBHOOK`, `PUSHOVER_USER_KEY` + `PUSHOVER_API_TOKEN`, `TELEGRAM_BOT_TOKEN` + `TELEGRAM_CHAT_ID`

## License

MIT
