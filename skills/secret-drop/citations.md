# secret-drop citations

Every claim SKILL.md makes about the code, with the place that proves it.

| kind | path | symbol | note |
| --- | --- | --- | --- |
| command | secret_drop.py | _open_command | opens a slot and sends the one-time link |
| flag | secret_drop.py | new_slot | --name names the slot, --file is the target, --reason is one line |
| behavior | secret_drop.py | check_target | the target must sit inside a directory the settings allow |
| behavior | secret_drop.py | find_open_by_token | the link works once and expires |
| command | secret_drop.py | _status_command | shows one slot and waits while it is open |
| flag | secret_drop.py | _status_command | --wait takes seconds from 0 to 3600 |
| exit | secret_drop.py | _status_command | 0 stored, 3 finished without a value, 4 still open |
| behavior | secret_drop.py | _expire_sweep | an expired slot finishes without a value |
| flag | secret_drop.py | new_slot | --replace replaces an open slot of the same name |
| flag | secret_drop.py | check_target | --overwrite lets the value replace an existing file |
