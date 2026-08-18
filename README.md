# Za — Zepto-Agent

Za is a local Linux micro-agent powered by
`Qwen/Qwen2.5-Coder-1.5B-Instruct`, focused on files, directories, filesystems,
mounted devices, and disk-space operations. The model is loaded directly with
Transformers; Ollama and llama.cpp are not required.

Za inventories installed applications, retrieves machine-compatible procedures,
and asks the model only when deterministic resolution is insufficient. Every
proposed Python, Bash, or Fish script is shown before execution and can be edited
or cancelled. Pressing Enter approves normal-risk code; elevated-risk operations
require typing `approve`.

Approved procedures and execution outcomes are stored in a machine-specific
SQLite database. Successful procedures become `verified` and, after three
successful uses, `trusted`. Model weights are never modified.

## Requirements and installation

- Python 3.10 or newer
- About 4 GB of disk space for the model
- Enough memory to load a 1.5B model (BF16 is used on CPU; FP16 on CUDA)

```bash
python3 -m venv .venv
source .venv/bin/activate
python3 -m pip install -r requirements.txt
```

## Run

```bash
./za.py
```

The model downloads only when absent and remains resident for the interactive
session. Its existing Hugging Face cache is preserved at
`~/.local/share/za/models` by default. Machine state is stored under
`~/.cache/za/machines/<machine-hash>/`; override the base with `--cache-dir`
or `ZA_CACHE_DIR`, and the model cache with `ZA_MODEL_CACHE`.

Approved scripts start in the background (`&`). Za captures their standard
output and errors in a terminal view with separate `Output` and `Errori`
sections. The view shows the process status, wraps long lines, and follows new
output automatically. The arrow keys and mouse wheel scroll the active section;
Enter/`s` records success, `n` records failure, and Esc returns without recording
feedback.

## Maintenance commands

```bash
./za.py --scan
./za.py --list-apps
./za.py --find-app gimp
./za.py --find-files report
./za.py --list-skills
./za.py --skill launch-application
./za.py --revoke-skill NAME
./za.py --delete-skill NAME
./za.py --diagnose
./za.py --benchmark
./za.py --rebuild-cache
```

`--rebuild-cache` removes and rebuilds only scanner-derived data. Learned
procedures and execution history are retained. A corrupt database is preserved
with a timestamped `.corrupt-*.sqlite` name before a clean index is created.

When a fresh proposal is needed, Za also navigates the filesystem read-only: it
matches file and folder names against the request and hands the real existing
paths (plus short, redacted previews of small text files) to the model, so
proposed commands reference actual locations instead of invented ones.
`--find-files QUERY` performs the same name search from the command line and
prints `path<TAB>kind<TAB>size` without loading the model.

## Test

Tests use temporary directories, simulated external commands, and never download
or load the model:

```bash
python3 -m py_compile za.py
./za.py --self-test
./za.py --help
```

For optional runtime timings, use `--benchmark`; generation metrics include model
load time, time to first token, output tokens, and tokens per second when a model
generation has occurred in the current process.
