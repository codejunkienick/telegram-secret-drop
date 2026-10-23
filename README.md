# secret-drop

Secret-drop is an add-on for the Telegram bridge pack. It lets an agent ask the user for a secret without seeing it.

## what it does

The flow has five steps.

1. The agent opens a slot for one secret.
2. The user gets a one-time link in the paired chat.
3. The user opens the link on a phone on the same LAN.
4. The user pastes the value into the form.
5. The file is written owner-only, and the agent learns only whether it was stored and its length.

Telegram never carries the value. The value travels only from the phone to this host.

## requirements

Linux. Python 3.11 or later. A systemd user session. The Telegram bridge pack imported in the city with its reply-current command.

## install

Copy the example settings to `~/.config/secret-drop/settings.toml` and make the file owner-only:

```
mkdir -p ~/.config/secret-drop
cp settings.example.toml ~/.config/secret-drop/settings.toml
chmod 600 ~/.config/secret-drop/settings.toml
```

Edit the file. Set `lan_address` to the address of the LAN interface the phone can reach, for example `192.168.1.20`. Set `port`, for example `8765`. Set `allowed_dirs` to the directories a secret may be written under. Each one must exist, be owned by the user, and not be writable by group or others. Set `python` to an interpreter outside any home directory. `check`, `render-unit` and `install.sh` refuse a python under `/home`, `/root` or `$HOME`.

Check the settings, create the slots dir and write the unit:

```
./install.sh --settings ~/.config/secret-drop/settings.toml
```

The script creates the slots dir with mode 700 and writes the unit file with mode 644. It never starts, enables or stops a unit. Then reload the user units:

```
systemctl --user daemon-reload
```

After changing allowed_dirs, slots_dir or python, run install.sh and `systemctl --user daemon-reload` again.

Add the pack to the city. Put this in the city pack.toml, with source set to the repository path or URL:

```toml
[imports.secret]
source = "/home/alex/src/telegram-secret-drop"
```

Then run `gc reload`. If the host has a firewall, allow the port from the LAN.

## settings

| key | default | meaning |
| --- | --- | --- |
| lan_address | required | LAN address the form server binds to |
| port | required | TCP port the form server listens on, from 1024 to 65535 |
| allowed_dirs | required | List of 1 to 32 directories a secret may be written under |
| slots_dir | ~/.local/state/secret-drop | Directory that holds the slot records |
| send_command | ["gc", "telegram", "reply-current"] | Command used to send the one-time link |
| unit | secret-drop.service | On-demand unit that serves the form |
| python | /usr/bin/python3 | Interpreter the unit runs |

`lan_address` must be a LAN, VPN or loopback address. `allowed_dirs` entries must be absolute paths without symlinks, owned by the user and not writable by group or others. The settings file itself must be owner-only, so keep its mode at 600.

## using it

The agent side has four commands. Each prints one JSON line.

`gc secret open --name NAME --file PATH --reason "one line"` opens a slot. PATH is the file the consuming program will read, inside a directory the settings allow. It prints the slot name, its expiry time and `"link": "sent"`. It exits 0 on success and 1 when the slot cannot be opened or the link cannot be sent. `--ttl-minutes` sets how many minutes the link lives, from 1 to 30; the default is 10. `--replace` replaces an open slot of the same name. `--overwrite` lets the value replace an existing file.

`gc secret status NAME --wait SECONDS` shows one slot. It prints the name, state, path, length, stored time, expiry time and error. It waits while the slot is open, up to SECONDS, from 0 to 3600; the default is 0. It exits 0 when stored, 3 when finished without a value, and 4 when still open. It exits 1 when there is no such slot or --wait is outside 0 to 3600.

`gc secret cancel NAME` cancels one open slot. It prints the slot and exits 0. It exits 1 when there is no such slot or the slot is not open.

`gc secret list` lists slots by name. It prints one JSON array and exits 0.

Values are one line. Control characters are refused, so a multi-line value cannot be stored. The value is stripped of surrounding whitespace, must be 1 to 16384 bytes, and is stored without a trailing newline. Names match [a-z0-9][a-z0-9._-]{0,63} and cannot be "server". Reasons are printable and at most 200 characters. Target paths and allowed_dirs use only letters, digits and . _ @ + / -. A file name with a space is refused as target_bad_path. The form answers a rejected value with only "The value was not accepted. Try again.".

What the user sees: a link in the paired chat that works once and expires. The link opens a form showing the slot name, the reason, the file and the expiry time. After storing, the page says the value was stored and the page can be closed. A value the form rejects shows a retry line. A value that cannot be stored shows Not stored, and the agent must open a new link. A link that is used, expired or unknown shows a not found page.

## how it works

Open starts the unit through the user session. The unit serves the form. When no slot is open, the server stops, so the port listens only while a slot is open.

Each link holds a 256 bit token. The token is stored only as a hash. Each token works once. A slot lives from 1 to 30 minutes. Reading the form with GET never consumes the link.

The value is written atomically with mode 0600. It lands inside one of the allowed dirs. The write never follows a symlink. Parent directories must stay owned by the user and not writable by group or others, and the write refuses anything else.

## security

What it protects: the value never passes through Telegram, GC, the agent transcript or a model provider. The link is useless off the LAN and after one use or its expiry. The port listens only while a slot is open. Where the kernel allows unprivileged user namespaces, systemd runs the unit with ProtectHome=tmpfs, read-only binds for the script dir and the settings file, write binds for the slots dir and the allowed dirs, and its private /tmp. Run `systemd-analyze --user security UNIT` to check, with UNIT set to the unit name from the settings.

What it does not: the form uses plain HTTP. On a WPA2 network, anyone who knows the Wi-Fi passphrase and captures the phone handshake can read the exchange. A compromised device on the LAN can intercept or alter the request because nothing authenticates the server. A VPN protects only up to where it ends. A VPN that ends on the router leaves the last hop plain. A VPN that ends on this host, with lan_address set to its VPN address, covers the whole path. Every agent runs as the same Unix user and could read the file. The add-on keeps the value out of every channel and transcript but is no wall against an agent that reads it anyway. Keyboard apps, clipboard managers and password managers on the phone can see the value. Telegram keeps the link, which is dead once used or expired. Anyone who sees the open link and can reach the port can store a value first. The agent then gets stored with a value the user did not choose, and the user sees a not found page. Tell the agent what happened and rotate the value. The form shows the slot name, the reason and the full target path to anyone with the link. Any host on the LAN can keep the form from loading while it keeps connecting. A request without an Origin header is accepted, as some non-browser clients send none; it still needs the one-time token.

## uninstall

Stop the unit, using the unit name from the settings (the default is secret-drop.service):

```
systemctl --user stop secret-drop.service
```

Remove the unit file of that same name from `~/.config/systemd/user/` (or `$XDG_CONFIG_HOME/systemd/user/` when set), then reload:

```
systemctl --user daemon-reload
```

Remove `[imports.secret]` from the city pack.toml and run `gc reload`. Optionally delete the slots dir and the settings file.

## tests

Run the suite from the repository root:

```
python3 -B -m unittest discover -s . -p 'test_*.py'
```

The tests are offline and fake-only. They use temporary directories and example values.
