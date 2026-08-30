# Za — Zepto-Agent

Za is a Linux micro-agent focused on files, directories, filesystems, mounted
devices, and disk-space operations. It sends generation requests to the local
FreeLLMAPI gateway at `http://127.0.0.1:3001` through the OpenAI-compatible
`/v1/chat/completions` endpoint and uses the `auto` routing model. Za has no
local-model backend and downloads no model weights.

Za inventories installed applications, retrieves machine-compatible procedures,
and asks the model only when deterministic resolution is insufficient. Every
proposed Python, Bash, or Fish script is shown before execution and can be edited
or cancelled. Pressing Enter approves normal-risk code; elevated-risk operations
require typing `approve`.

When the proposal comes from a stored procedure, the approval prompt also shows
`d elimina procedura`. Pressing `d` deletes that procedure and all its versions
from the database without executing it. Existing execution and feedback history
is retained, but is no longer linked to the deleted procedure.

Approved procedures and execution outcomes are stored in a machine-specific
SQLite database. Successful procedures become `verified` and, after three
successful uses, `trusted`.

## Requirements and installation

- Python 3.10 or newer
- `secret-tool` for the system keyring
- A FreeLLMAPI gateway listening on port 3001

```bash
chmod +x za.py
mkdir -p ~/.local/bin
ln -s "$(pwd)/za.py" ~/.local/bin/za
```

Za uses only the Python standard library; `requirements.txt` is kept as an
explicit record that no Python packages are required.

## Run

```bash
za
```

The first time a generated proposal is needed, Za asks for the FreeLLMAPI
unified key without echoing it and stores it in the system keyring with
`application=freellmapi` and `account=default`. Later runs read it from there;
the key is not read from environment variables or project files. Machine state
is stored under `~/.cache/za/machines/<machine-hash>/`; override the base with
`--cache-dir` or `ZA_CACHE_DIR`.

### Start FreeLLMAPI at boot

The included user service starts the existing Docker Compose installation from
`~/freellmapi`. Link and enable it once:

```bash
mkdir -p ~/.config/systemd/user
ln -s "$(pwd)/freellmapi.service" ~/.config/systemd/user/freellmapi.service
systemctl --user daemon-reload
systemctl --user enable --now freellmapi.service
loginctl enable-linger "$USER"
sudo systemctl enable --now docker.socket
```

Lingering lets the user service start during boot without waiting for an
interactive login. The system Docker socket must also be enabled.

Approved scripts start in the background (`&`). Za captures their standard
output and errors in a terminal view with separate `Output` and `Errori`
sections. The view shows the process status, wraps long lines, and follows new
output automatically. The arrow keys and mouse wheel scroll the active section;
Enter/`s` records success, `n` records failure, and Esc returns without recording
feedback.

## Maintenance commands

```bash
za --scan
za --list-apps
za --find-app gimp
za --find-files report
za --list-skills
za --skill launch-application
za --revoke-skill NAME
za --delete-skill NAME
za --diagnose
za --benchmark
za --rebuild-cache
```

`--rebuild-cache` removes and rebuilds only scanner-derived data. Learned
procedures and execution history are retained. A corrupt database is preserved
with a timestamped `.corrupt-*.sqlite` name before a clean index is created.
Application and learned-procedure searches expand a bounded Italian/English
synonym map before querying exact matches, FTS5, SQL fallback, and fuzzy ranking.
This lets equivalent terms such as `navigatore`/`browser` and
`copia`/`duplica` find the same stored item without calling FreeLLMAPI.

When a fresh proposal is needed, Za also navigates the filesystem read-only: it
matches file and folder names against the request and hands the real existing
paths (plus short, redacted previews of small text files) to the model, so
proposed commands reference actual locations instead of invented ones.
Before generation, Za corrects user-supplied paths only when the filesystem
match is unique. It then applies the same case-sensitive check to every literal
path in model-generated code and rejects proposals containing unresolved paths.
Requests with a creation intent (`crea`, `copia`, `sposta`, `rinomina`, ...) may
legitimately name paths that do not exist yet: Za resolves the longest existing
prefix, keeps the new tail as typed, and only then accepts the same paths in the
model code. If a generation is not valid JSON or refers to an unresolved path,
Za asks the model once to correct itself, appending the reason, before giving up.
Before retrying, Za tries to repair common malformations in the model output
(unquoted keys, trailing commas, single quotes, comments) and requires `code` to
be non-empty.
`--find-files QUERY` performs the same name search from the command line and
prints `path<TAB>kind<TAB>size` without calling FreeLLMAPI.

## Test

Tests use temporary directories and simulated external commands. They never
contact FreeLLMAPI or read/write the real keyring:

```bash
python3 -m py_compile za.py
./za.py --self-test
./za.py --help
systemd-analyze --user verify freellmapi.service
```

For optional runtime timings, use `--benchmark`; after a generation in the
current process its metrics include request time, token usage, and the provider
selected by the FreeLLMAPI router.
