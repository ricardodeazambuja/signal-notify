# Tutorial: Setting Up Native Signal Self-Notifications (Note-to-Self)

This tutorial walks you through setting up `signal-notify` to send automated notifications directly to your own Signal account (**Note-to-Self** chat) using the pure-Python native mode. 

No Java runtime, no compilers, and no binary downloads are required.

---

## Prerequisites

1. An active Signal account on your primary phone.
2. A machine running Python ≥ 3.9.
3. Access to a terminal.

---

## Step 1: Install `signal-notify`

Clone the repository and install the package:

```sh
git clone https://github.com/ricardodeazambuja/signal-notify.git
cd signal-notify
pip install -e .
```

*Note: This automatically installs all required dependencies (`cryptography`, `websockets`, `qrcode`, and `PyYAML`).*

---

## Step 2: Configure Your Phone for Full Notifications

To get the actual message body on your lock screen / Apple Watch (instead of a generic "New Message" indicator), configure these settings on your phone:

1. **Signal App Settings:**
   * Open Signal → Tap your profile icon (Settings) → **Notifications**.
   * Set **Show** to: **"Name, Content, and Actions"**.
2. **Phone Operating System Settings (iOS / Android):**
   * Go to System Settings → Notifications → **Signal**.
   * Set **Show Previews** to: **"Always"**.

---

## Step 3: Link Your Machine Natively

To link this machine to your phone's Signal account:

1. Run the linking command with a custom device name (e.g., `server-alerts`):
   ```sh
   signal-notify link -n "server-alerts"
   ```
2. A QR code will be rendered in your terminal.
3. Open Signal on your primary phone:
   * **Settings** → **Linked Devices** → Tap **"+"** (iOS) or **"Link New Device"** (Android).
4. Scan the QR code displayed in the terminal.
5. Confirm linking on your phone.

Once successful, your credentials will be securely written with owner-only permissions (`0o600`) to your default data directory:
`~/.local/share/signal-notify/data`

---

## Step 4: Send Your First Test Message

Verify that native message sending is operational by sending a message directly to your own account's Note-to-Self chat:

```sh
signal-notify send -m "Hello from my server! 🚀"
```

You should receive a push notification instantly on your phone and watch, and see the message in your Note-to-Self chat.

---

## Step 5: Configure the Orchestrated Monitoring Daemon

For cron jobs or automated scripts, `signal-notify` includes a config-driven notification orchestrator that diffs alert states to ensure you get notified **exactly once** for a standing alert (deduplication).

1. Create a configuration file named `notify.yaml` with `native: true` enabled:
   ```yaml
   channels:
     signal:
       enabled: true
       native: true
       note_to_self: true

   # Prepend emojis for readability
   prefixes:
     "ERROR": "🛑"
     "WARNING": "⚠️"
     "SUCCESS": "✅"

   # Quiet hours settings (optional)
   quiet_hours:
     enabled: true
     start: "22:00"
     end: "07:00"

   # Bypass quiet hours for critical issues
   critical_keywords:
     - "ERROR"
   ```

2. Point your automated monitoring scripts to write current active alert lines to a file (e.g. `active.txt`):
   ```sh
   echo "WARNING: Disk usage is 85%" > active.txt
   echo "ERROR: Backup task failed" >> active.txt
   ```

3. Run the orchestrator:
   ```sh
   signal-notify run --config notify.yaml --active active.txt --notified notified.txt
   ```

* **How it works:** `signal-notify` compares `active.txt` with `notified.txt`. Since these two alerts are new, it formats and sends them. It then saves the state to `notified.txt`.
* If you run the command again, it detects no new changes and remains silent.
* If the warning resolves and drops from `active.txt`, it will be cleared from `notified.txt`. If it occurs again later, you will receive another alert.

---

## Step 6: Automate via Cron

To run the check every 5 minutes:

1. Open your crontab:
   ```sh
   crontab -e
   ```
2. Add a line to execute your alert collection and running commands (make sure paths are absolute):
   ```cron
   */5 * * * * /path/to/my_alert_script.sh && /usr/local/bin/signal-notify run --config /path/to/notify.yaml --active /path/to/active.txt --notified /path/to/notified.txt
   ```
