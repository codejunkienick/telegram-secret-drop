---
name: secret-drop
description: Ask the user for a secret (an API key, token or password) without seeing it. Use when a program needs a secret value that the agent must never see, and the settings allow the target directory.
---

Never ask for a secret in chat. Pick the file the consuming program will read. The file must sit inside a directory the settings allow.

Run `gc secret open --name NAME --file PATH --reason "one line"`. NAME names the slot. PATH is the file the consuming program will read. Use one line of reason text.

The user gets a one-time link in the paired chat. The link works once and expires. Then run `gc secret status NAME --wait 600`.

Exit 0 means stored. Exit 3 means finished without a value. Exit 4 means still open.

Never read, print, copy, hash, grep or cat the target. Hand the consuming program the path instead. Point it at the file with its key-file option, or give it an environment file it reads itself.

On expired, ask once whether to open a new link. With --replace, open replaces an open slot of the same name. With --overwrite, the value replaces an existing file.

If the user pastes a secret in chat anyway, do not repeat it. Suggest rotating it.
