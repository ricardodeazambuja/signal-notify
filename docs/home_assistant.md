# Home Assistant Integration

Push Home Assistant notifications to your phone through Signal's
**Note-to-Self** chat — end-to-end encrypted, no Signal bot number, no
third-party push service, no open ports. `signal-notify` is pure Python, so it
runs happily next to Home Assistant on the same Raspberry Pi / Jetson / x86
box.

All patterns below assume you have already **installed and linked once**:

```sh
pip install signal-notify
signal-notify link            # scan the QR with your phone (one time)
signal-notify send -m "hello from Home Assistant"   # sanity check
```

> **Run `link` as the same user Home Assistant runs as** (e.g.
> `sudo -u homeassistant signal-notify link`). The linked-device state lives in
> `~/.local/share/signal-notify/data` of whoever ran `link`; you can relocate
> it with the `SIGNALNOTIFY_DATA_DIR` environment variable.

> **Which HA install types does this work with?** Home Assistant **Core**
> (venv) and **Container** setups can call the CLI directly as shown below
> (for Container, install signal-notify on the host and use the
> `shell_command` pattern pointing at the host via SSH, or bake it into a
> derived image). On **Home Assistant OS** there is no host shell to install
> into — run signal-notify on any other machine on your network, or inside a
> custom add-on container.

## Pattern 1 — `shell_command` (simplest)

`configuration.yaml`:

```yaml
shell_command:
  # NOTE: single-quote the template so spaces survive the shell.
  signal_notify: "signal-notify send -m '{{ message }}'"
```

Use it from any automation:

```yaml
automation:
  - alias: "Door opened while away"
    trigger:
      - platform: state
        entity_id: binary_sensor.front_door
        to: "on"
    condition:
      - condition: state
        entity_id: person.me
        state: "not_home"
    action:
      - service: shell_command.signal_notify
        data:
          message: "🚪 Front door opened at {{ now().strftime('%H:%M') }}"
```

If `signal-notify` is not on Home Assistant's `PATH`, use the absolute path to
the console script (e.g. `/srv/homeassistant/bin/signal-notify`).

## Pattern 2 — a real `notify` service (`command_line`)

This makes Signal a first-class notify target, usable anywhere a
`notify.<name>` service is accepted (alerts, `notify` actions, the `alert`
integration):

```yaml
notify:
  - name: signal
    platform: command_line
    command: 'signal-notify send -m "$(cat)"'
```

The `command_line` notify platform pipes the message on **stdin**, hence the
`"$(cat)"`. Then:

```yaml
action:
  - service: notify.signal
    data:
      message: "Backup finished OK ✅"
```

## Pattern 3 — Python API (attachments, e.g. camera snapshots)

For anything richer than text — like sending a camera snapshot when motion is
detected — call the library from AppDaemon, [pyscript](https://github.com/custom-components/pyscript),
or any external script:

```python
from signalnotify import send_message

# text + an encrypted image attachment, straight to your Note-to-Self chat
send_message("🎥 Motion at the front door", attachments=["/tmp/front_door.jpg"])
```

Wired to a snapshot automation:

```yaml
automation:
  - alias: "Motion snapshot to Signal"
    trigger:
      - platform: state
        entity_id: binary_sensor.front_door_motion
        to: "on"
    action:
      - service: camera.snapshot
        target:
          entity_id: camera.front_door
        data:
          filename: /tmp/front_door.jpg
      - service: shell_command.signal_snapshot

shell_command:
  signal_snapshot: "signal-notify send -m '🎥 Motion at the front door' --attach /tmp/front_door.jpg"
```

## Pattern 4 — alert batching, quiet hours, dedupe (`run`)

If your automations write alert lines to a file instead of pushing directly,
`signal-notify run` gives you deduping, keyword filtering, quiet hours and
batching for free — see [Config-Driven Alert Monitoring](../README.md#-config-driven-alert-monitoring-run)
and [`notify.example.yaml`](../notify.example.yaml). Trigger it from a cron
job or an HA time-pattern automation via `shell_command`.

## Two-way: reacting to your replies

Everything you type back into Note-to-Self on your phone is readable by the
same linked device. A small daemon can turn that into HA actions (toggle a
light by texting yourself `lights on`):

```python
from signalnotify import listen
import urllib.request, json

HA = "http://homeassistant.local:8123"
TOKEN = "..."  # long-lived access token

def handle(msg):
    if not msg.note_to_self or not msg.body:
        return
    if msg.body.strip().lower() == "lights on":
        req = urllib.request.Request(
            f"{HA}/api/services/light/turn_on",
            data=json.dumps({"entity_id": "light.living_room"}).encode(),
            headers={"Authorization": f"Bearer {TOKEN}",
                     "Content-Type": "application/json"})
        urllib.request.urlopen(req)

listen(handle)   # persistent connection; reconnects with backoff
```

See [`examples/agent_daemon.py`](../examples/agent_daemon.py) for the general
daemon skeleton and [Customizing](customizing.md) for the full API.

## Troubleshooting

- `signal-notify doctor` — checks the account link and service reachability
  (exit code 0 = healthy), handy as an HA `command_line` binary sensor.
- "no native Signal account configuration found (run: signal-notify link)" —
  the user running the command isn't the one that ran `link`, or
  `SIGNALNOTIFY_DATA_DIR` points elsewhere.
- Messages send but the phone shows no preview text — check your phone's
  notification-preview setting (see the
  [tutorial](tutorial_self_notifications.md)).
