#!/usr/bin/env python3
"""Za: a small, local, learning Linux agent."""

import argparse
import configparser
import contextlib
import curses
import dataclasses
import difflib
import hashlib
import json
import os
import re
import readline
import shlex
import shutil
import signal
import sqlite3
import subprocess
import sys
import tempfile
import textwrap
import threading
import time
from pathlib import Path


MODEL = "Qwen/Qwen2.5-Coder-1.5B-Instruct"
LOGO_TEXT = (
    "",
    " ▀▀█ █▀█",
    " ▄▀  █▀█",
    " ▀▀▀ ▀ ▀",
)
SCHEMA_VERSION = 2
OUTPUT_LIMIT = 64 * 1024
LANGUAGE_ALIASES = {
    "python": "python", "python3": "python", "bash": "bash",
    "sh": "bash", "shell": "bash", "fish": "fish",
}
INTERPRETERS = {
    "python": ("python3", ".py"), "bash": ("bash", ".sh"),
    "fish": ("fish", ".fish"),
}

ANSI_BOLD = "\033[1m"
ANSI_DIM = "\033[2m"
ANSI_CYAN = "\033[36m"
ANSI_GREEN = "\033[32m"
ANSI_YELLOW = "\033[33m"
ANSI_RED = "\033[31m"
ANSI_BLUE = "\033[34m"
ANSI_MAGENTA = "\033[35m"
ANSI_GRAY = "\033[90m"
ANSI_RESET = "\033[0m"
ANSI_ESCAPE = re.compile(r"\x1b\[[0-?]*[ -/]*[@-~]")
ANSI_RAINBOW = ("\033[38;2;255;35;35m", "\033[38;2;255;225;0m",
                "\033[38;2;0;255;85m", "\033[38;2;0;240;255m",
                "\033[38;2;55;115;255m", "\033[38;2;255;35;220m")
def machine_hash():
    try:
        identity = Path("/etc/machine-id").read_text(encoding="utf-8").strip()
    except OSError:
        identity = os.uname().nodename
    return hashlib.sha256(identity.encode()).hexdigest()[:16]


@dataclasses.dataclass
class Config:
    cache_dir: Path
    model_cache: Path
    scan_ttl: int = 3600
    timeout: int = 120
    max_new_tokens: int = 768
    repetition_penalty: float = 1.05
    verbose: bool = False
    appimage_dirs: tuple = ()

    @classmethod
    def create(cls, cache_dir=None, verbose=False):
        base = Path(cache_dir or os.environ.get(
            "ZA_CACHE_DIR",
            Path(os.environ.get("XDG_CACHE_HOME", Path.home() / ".cache")) / "za",
        )).expanduser()
        model_cache = Path(os.environ.get(
            "ZA_MODEL_CACHE",
            Path(os.environ.get("XDG_DATA_HOME", Path.home() / ".local" / "share"))
            / "za" / "models",
        )).expanduser()
        configured = os.environ.get("ZA_APPIMAGE_DIRS")
        app_dirs = tuple(Path(p).expanduser() for p in configured.split(os.pathsep)) if configured else (
            Path.home() / "Applications", Path.home() / "AppImages",
            Path("/opt"), Path("/usr/local/bin"),
        )
        return cls(base / "machines" / machine_hash(), model_cache,
                   verbose=verbose, appimage_dirs=app_dirs)


def terminal_style(text, *codes):
    if not sys.stdout.isatty():
        return str(text)
    return f"{''.join(codes)}{text}{ANSI_RESET}"


def show_status(symbol, message, color=ANSI_CYAN):
    print(f"{terminal_style(symbol, color)}  {message}")


def logo_lines():
    return ["".join(
        terminal_style(char, ANSI_RAINBOW[i * len(ANSI_RAINBOW) // len(line)])
        if char != " " else char for i, char in enumerate(line)
    ) for line in LOGO_TEXT]


def terminal_header():
    return "\n".join((*logo_lines(),
                      "Micro-agente Linux locale", terminal_style(MODEL, ANSI_DIM),
                      terminal_style(str(Path.cwd()), ANSI_DIM)))


def terminal_separator():
    return terminal_style("─" * shutil.get_terminal_size(fallback=(80, 24)).columns, ANSI_DIM)


def terminal_prompt():
    return "> " if not sys.stdout.isatty() else "\001\033[1;36m\002>\001\033[0m\002 "


class SystemDatabase:
    """Machine-local structured state. A corrupt DB is retained for recovery."""

    def __init__(self, path):
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.recovered_path = None
        try:
            self.connection = sqlite3.connect(self.path)
            self.connection.row_factory = sqlite3.Row
            result = self.connection.execute("PRAGMA quick_check").fetchone()[0]
            if result != "ok":
                raise sqlite3.DatabaseError(result)
            self._create_schema()
        except sqlite3.DatabaseError:
            with contextlib.suppress(Exception):
                self.connection.close()
            self.recovered_path = self.path.with_suffix(f".corrupt-{int(time.time())}.sqlite")
            if self.path.exists():
                self.path.replace(self.recovered_path)
            self.connection = sqlite3.connect(self.path)
            self.connection.row_factory = sqlite3.Row
            self._create_schema()

    def _create_schema(self):
        self.connection.executescript("""
            PRAGMA journal_mode=WAL;
            PRAGMA foreign_keys=ON;
            CREATE TABLE IF NOT EXISTS schema_info(version INTEGER NOT NULL);
            CREATE TABLE IF NOT EXISTS applications(
              id INTEGER PRIMARY KEY, source TEXT NOT NULL, identifier TEXT NOT NULL,
              name TEXT NOT NULL, path TEXT, description TEXT, launch_json TEXT NOT NULL,
              metadata_json TEXT NOT NULL DEFAULT '{}', fingerprint TEXT, updated_at REAL NOT NULL,
              UNIQUE(source, identifier));
            CREATE INDEX IF NOT EXISTS applications_name ON applications(name COLLATE NOCASE);
            CREATE TABLE IF NOT EXISTS aliases(
              alias TEXT COLLATE NOCASE NOT NULL, application_id INTEGER NOT NULL,
              UNIQUE(alias, application_id), FOREIGN KEY(application_id) REFERENCES applications(id) ON DELETE CASCADE);
            CREATE INDEX IF NOT EXISTS aliases_name ON aliases(alias COLLATE NOCASE);
            CREATE TABLE IF NOT EXISTS capabilities(
              application_id INTEGER NOT NULL, capability TEXT NOT NULL,
              UNIQUE(application_id, capability), FOREIGN KEY(application_id) REFERENCES applications(id) ON DELETE CASCADE);
            CREATE TABLE IF NOT EXISTS skills(
              id INTEGER PRIMARY KEY, name TEXT NOT NULL UNIQUE, description TEXT NOT NULL,
              intents_json TEXT NOT NULL DEFAULT '[]', examples_json TEXT NOT NULL DEFAULT '[]',
              parameters_json TEXT NOT NULL DEFAULT '{}', prerequisites TEXT NOT NULL DEFAULT '',
              risk TEXT NOT NULL DEFAULT 'normal', status TEXT NOT NULL DEFAULT 'proposed',
              successes INTEGER NOT NULL DEFAULT 0, failures INTEGER NOT NULL DEFAULT 0,
              machine_hash TEXT NOT NULL, current_version INTEGER NOT NULL DEFAULT 1,
              created_at REAL NOT NULL, updated_at REAL NOT NULL);
            CREATE INDEX IF NOT EXISTS skills_status ON skills(status);
            CREATE TABLE IF NOT EXISTS skill_versions(
              id INTEGER PRIMARY KEY, skill_id INTEGER NOT NULL, version INTEGER NOT NULL,
              request TEXT NOT NULL, normalized_intent TEXT NOT NULL,
              generated_code TEXT NOT NULL, approved_code TEXT NOT NULL,
              diff_summary TEXT NOT NULL, language TEXT NOT NULL,
              template_json TEXT, template_status TEXT NOT NULL DEFAULT 'proposed',
              verification TEXT NOT NULL, model TEXT NOT NULL,
              status TEXT NOT NULL, created_at REAL NOT NULL, UNIQUE(skill_id, version),
              FOREIGN KEY(skill_id) REFERENCES skills(id) ON DELETE CASCADE);
            CREATE INDEX IF NOT EXISTS skill_versions_intent ON skill_versions(normalized_intent);
            CREATE TABLE IF NOT EXISTS executions(
              id INTEGER PRIMARY KEY, skill_id INTEGER, skill_version INTEGER,
              request TEXT NOT NULL, normalized_intent TEXT NOT NULL,
              generated_code TEXT NOT NULL, approved_code TEXT NOT NULL,
              parameters_json TEXT NOT NULL, exit_code INTEGER, stdout TEXT, stderr TEXT,
              semantic_ok INTEGER NOT NULL, result TEXT NOT NULL, model TEXT NOT NULL,
              created_at REAL NOT NULL, FOREIGN KEY(skill_id) REFERENCES skills(id));
            CREATE TABLE IF NOT EXISTS feedback(
              id INTEGER PRIMARY KEY, execution_id INTEGER, kind TEXT NOT NULL,
              value TEXT NOT NULL, created_at REAL NOT NULL,
              FOREIGN KEY(execution_id) REFERENCES executions(id));
            CREATE TABLE IF NOT EXISTS scanner_metadata(
              key TEXT PRIMARY KEY, value TEXT NOT NULL, updated_at REAL NOT NULL);
        """)
        row = self.connection.execute("SELECT version FROM schema_info LIMIT 1").fetchone()
        if row is None:
            self.connection.execute("INSERT INTO schema_info VALUES (?)", (SCHEMA_VERSION,))
        elif row[0] < SCHEMA_VERSION:
            columns = {item[1] for item in self.connection.execute("PRAGMA table_info(skill_versions)")}
            if "template_status" not in columns:
                self.connection.execute("ALTER TABLE skill_versions ADD COLUMN template_status TEXT NOT NULL DEFAULT 'proposed'")
            self.connection.execute("UPDATE schema_info SET version=?", (SCHEMA_VERSION,))
        self.fts = True
        try:
            self.connection.executescript("""
                CREATE VIRTUAL TABLE IF NOT EXISTS applications_fts USING fts5(
                  app_id UNINDEXED, name, description, categories, aliases);
                CREATE VIRTUAL TABLE IF NOT EXISTS skills_fts USING fts5(
                  skill_id UNINDEXED, name, description, intents, examples);
            """)
        except sqlite3.OperationalError:
            self.fts = False
        self.connection.commit()

    def close(self):
        self.connection.close()

    def metadata(self, key, default=None):
        row = self.connection.execute(
            "SELECT value FROM scanner_metadata WHERE key=?", (key,)).fetchone()
        return row[0] if row else default

    def set_metadata(self, key, value):
        self.connection.execute("""INSERT INTO scanner_metadata VALUES(?,?,?)
          ON CONFLICT(key) DO UPDATE SET value=excluded.value, updated_at=excluded.updated_at""",
                                (key, str(value), time.time()))
        self.connection.commit()

    def upsert_application(self, app):
        now = time.time()
        values = (app["source"], app["identifier"], app["name"], app.get("path"),
                  app.get("description", ""), json.dumps(app["launch"], ensure_ascii=False),
                  json.dumps(app.get("metadata", {}), ensure_ascii=False),
                  app.get("fingerprint", ""), now)
        self.connection.execute("""INSERT INTO applications
          (source,identifier,name,path,description,launch_json,metadata_json,fingerprint,updated_at)
          VALUES(?,?,?,?,?,?,?,?,?) ON CONFLICT(source,identifier) DO UPDATE SET
          name=excluded.name,path=excluded.path,description=excluded.description,
          launch_json=excluded.launch_json,metadata_json=excluded.metadata_json,
          fingerprint=excluded.fingerprint,updated_at=excluded.updated_at""", values)
        row = self.connection.execute(
            "SELECT id FROM applications WHERE source=? AND identifier=?",
            (app["source"], app["identifier"])).fetchone()
        app_id = row[0]
        self.connection.execute("DELETE FROM aliases WHERE application_id=?", (app_id,))
        aliases = {app["name"], app["identifier"], *app.get("aliases", [])}
        self.connection.executemany("INSERT OR IGNORE INTO aliases VALUES(?,?)",
                                    ((alias.strip(), app_id) for alias in aliases if alias.strip()))
        self.connection.execute("DELETE FROM capabilities WHERE application_id=?", (app_id,))
        self.connection.executemany("INSERT OR IGNORE INTO capabilities VALUES(?,?)",
                                    ((app_id, item) for item in app.get("capabilities", [])))

    def finish_scan(self, source, started):
        self.connection.execute("DELETE FROM applications WHERE source=? AND updated_at<?",
                                (source, started))
        self.rebuild_application_fts()
        self.connection.commit()

    def rebuild_application_fts(self):
        if not self.fts:
            return
        self.connection.execute("DELETE FROM applications_fts")
        self.connection.execute("""INSERT INTO applications_fts
          SELECT a.id,a.name,a.description,json_extract(a.metadata_json,'$.Categories'),
          coalesce(group_concat(l.alias,' '),'') FROM applications a
          LEFT JOIN aliases l ON l.application_id=a.id GROUP BY a.id""")

    def rebuild_regenerable(self):
        self.connection.executescript("""
          DELETE FROM aliases; DELETE FROM capabilities; DELETE FROM applications;
          DELETE FROM scanner_metadata;
        """)
        if self.fts:
            self.connection.execute("DELETE FROM applications_fts")
        self.connection.commit()


def desktop_exec_to_argv(command, name="", desktop_file=""):
    """Parse Desktop Entry Exec without invoking a shell."""
    try:
        words = shlex.split(command)
    except ValueError:
        return []
    result = []
    for word in words:
        if word in {"%f", "%F", "%u", "%U", "%i"}:
            continue
        word = word.replace("%c", name).replace("%k", desktop_file).replace("%%", "%")
        word = re.sub(r"%[fFuUick]", "", word)
        if word:
            result.append(word)
    return result


class SystemScanner:
    DESKTOP_DIRS = (
        Path.home() / ".local/share/applications", Path("/usr/local/share/applications"),
        Path("/usr/share/applications"),
        Path.home() / ".local/share/flatpak/exports/share/applications",
        Path("/var/lib/flatpak/exports/share/applications"),
    )

    def __init__(self, config, database, runner=subprocess.run):
        self.config, self.db, self.runner = config, database, runner

    def _fingerprint(self):
        parts = [os.environ.get("PATH", "")]
        for directory in (*self.DESKTOP_DIRS, *self.config.appimage_dirs):
            try:
                parts.append(f"{directory}:{directory.stat().st_mtime_ns}")
            except OSError:
                parts.append(f"{directory}:missing")
        return hashlib.sha256("\n".join(parts).encode()).hexdigest()

    def scan(self, force=False):
        started = time.monotonic()
        fingerprint = self._fingerprint()
        previous = self.db.metadata("scan_fingerprint")
        last = float(self.db.metadata("scan_time", "0"))
        if not force and previous == fingerprint and time.time() - last < self.config.scan_ttl:
            return {"cached": True, "seconds": time.monotonic() - started}
        counts = {
            "native": self.scan_native(), "desktop": self.scan_desktop(),
            "flatpak": self.scan_flatpak(), "appimage": self.scan_appimages(),
        }
        self.db.set_metadata("scan_fingerprint", fingerprint)
        self.db.set_metadata("scan_time", time.time())
        counts.update(cached=False, seconds=time.monotonic() - started)
        return counts

    def scan_native(self):
        started, found, seen = time.time(), 0, set()
        packages = self._debian_owners()
        for directory_text in os.environ.get("PATH", "").split(os.pathsep):
            directory = Path(directory_text or ".")
            try:
                entries = list(directory.iterdir())
            except OSError:
                continue
            for path in entries:
                try:
                    if path.name in seen or not path.is_file() or not os.access(path, os.X_OK):
                        continue
                    resolved = path.resolve()
                except OSError:
                    continue
                seen.add(path.name)
                self.db.upsert_application({
                    "source": "native", "identifier": path.name, "name": path.name,
                    "path": str(resolved), "description": "Executable available in PATH",
                    "launch": [str(resolved)], "aliases": [], "capabilities": ["execute"],
                    "metadata": {"debian_package": packages.get(str(resolved), "")},
                    "fingerprint": f"{resolved}:{resolved.stat().st_mtime_ns}",
                })
                found += 1
        self.db.finish_scan("native", started)
        return found

    def _debian_owners(self):
        if not shutil.which("dpkg-query"):
            return {}
        try:
            result = self.runner(["dpkg-query", "-S", "/usr/bin/*", "/bin/*"],
                                 capture_output=True, text=True, timeout=20, check=False)
        except (OSError, subprocess.SubprocessError):
            return {}
        owners = {}
        for line in result.stdout.splitlines():
            if ": " not in line:
                continue
            package, paths = line.split(": ", 1)
            for path in paths.split(", "):
                with contextlib.suppress(OSError):
                    owners[str(Path(path).resolve())] = package
        return owners

    def scan_desktop(self):
        started, found, seen = time.time(), 0, set()
        gtk_launch = shutil.which("gtk-launch")
        for directory in self.DESKTOP_DIRS:
            try:
                files = list(directory.glob("*.desktop"))
            except OSError:
                continue
            for path in files:
                desktop_id = path.name.removesuffix(".desktop")
                if desktop_id in seen:
                    continue
                parser = configparser.ConfigParser(interpolation=None, strict=False)
                try:
                    parser.read(path, encoding="utf-8")
                    entry = parser["Desktop Entry"]
                    if entry.get("Type", "Application") != "Application":
                        continue
                    name = entry.get("Name", desktop_id)
                    argv = ([gtk_launch, desktop_id] if gtk_launch else
                            desktop_exec_to_argv(entry.get("Exec", ""), name, str(path)))
                    if not argv:
                        continue
                    metadata = {key: entry.get(key, "") for key in (
                        "GenericName", "Comment", "Keywords", "Categories", "Exec",
                        "TryExec", "Terminal", "MimeType", "NoDisplay")}
                    self.db.upsert_application({
                        "source": "desktop", "identifier": desktop_id, "name": name,
                        "path": str(path), "description": " ".join(filter(None, (
                            metadata["GenericName"], metadata["Comment"]))),
                        "launch": argv, "metadata": metadata,
                        "aliases": [x for x in re.split(r"[;,]", metadata["Keywords"]) if x],
                        "capabilities": [x for x in metadata["MimeType"].split(";") if x],
                        "fingerprint": f"{path.stat().st_size}:{path.stat().st_mtime_ns}",
                    })
                    seen.add(desktop_id)
                    found += 1
                except (OSError, configparser.Error, KeyError, UnicodeError):
                    continue
        self.db.finish_scan("desktop", started)
        return found

    def scan_flatpak(self):
        started, found = time.time(), 0
        flatpak = shutil.which("flatpak")
        if flatpak:
            try:
                result = self.runner(
                    [flatpak, "list", "--app", "--columns=application,name,branch,installation"],
                    capture_output=True, text=True, timeout=20, check=False)
                for line in result.stdout.splitlines():
                    fields = line.split("\t")
                    if len(fields) < 1 or not fields[0]:
                        continue
                    app_id = fields[0]
                    name = fields[1] if len(fields) > 1 and fields[1] else app_id
                    metadata = {"branch": fields[2] if len(fields) > 2 else "",
                                "installation": fields[3] if len(fields) > 3 else ""}
                    self.db.upsert_application({
                        "source": "flatpak", "identifier": app_id, "name": name,
                        "description": f"Flatpak application {app_id}",
                        "launch": [flatpak, "run", app_id], "metadata": metadata,
                        "aliases": [app_id.rsplit(".", 1)[-1]], "capabilities": ["launch"],
                    })
                    found += 1
            except (OSError, subprocess.SubprocessError):
                pass
        self.db.finish_scan("flatpak", started)
        return found

    def scan_appimages(self):
        started, found, seen = time.time(), 0, set()
        for root in self.config.appimage_dirs:
            try:
                candidates = list(root.glob("*.AppImage"))
                candidates += [p for child in root.iterdir() if child.is_dir()
                               for p in child.glob("*.AppImage")]
            except OSError:
                continue
            for path in candidates:
                try:
                    resolved = path.resolve()
                    if resolved in seen or not resolved.is_file():
                        continue
                    stat = resolved.stat()
                except OSError:
                    continue
                seen.add(resolved)
                executable = os.access(resolved, os.X_OK)
                associated = next(iter(resolved.parent.glob(f"{resolved.stem}.desktop")), None)
                self.db.upsert_application({
                    "source": "appimage", "identifier": str(resolved),
                    "name": resolved.stem, "path": str(resolved),
                    "description": "Portable AppImage application",
                    "launch": [str(resolved)], "aliases": [resolved.stem.replace("-", " ")],
                    "capabilities": ["launch"],
                    "metadata": {"executable": executable, "size": stat.st_size,
                                 "mtime": stat.st_mtime, "desktop": str(associated or "")},
                    "fingerprint": f"{stat.st_size}:{stat.st_mtime_ns}",
                })
                found += 1
        self.db.finish_scan("appimage", started)
        return found


class ApplicationResolver:
    def __init__(self, database):
        self.db = database

    def _rows(self, sql, parameters):
        return [dict(row) for row in self.db.connection.execute(sql, parameters)]

    def search(self, query, limit=10):
        query = query.strip()
        exact = self._rows("SELECT * FROM applications WHERE name=? COLLATE NOCASE OR identifier=? COLLATE NOCASE LIMIT ?",
                           (query, query, limit))
        if exact:
            return exact
        alias = self._rows("""SELECT a.* FROM aliases l JOIN applications a ON a.id=l.application_id
                              WHERE l.alias=? COLLATE NOCASE LIMIT ?""", (query, limit))
        if alias:
            return alias
        if self.db.fts:
            safe = " ".join(re.findall(r"[\w.-]+", query, re.UNICODE))
            if safe:
                try:
                    rows = self._rows("""SELECT a.* FROM applications_fts f JOIN applications a ON a.id=f.app_id
                                         WHERE applications_fts MATCH ? ORDER BY rank LIMIT ?""",
                                      (safe, limit))
                    if rows:
                        return rows
                except sqlite3.OperationalError:
                    pass
        like = f"%{query}%"
        return self._rows("SELECT * FROM applications WHERE name LIKE ? OR description LIKE ? LIMIT ?",
                          (like, like, limit))

    def resolve_request(self, request):
        match = re.match(r"(?i)^\s*(?:apri|avvia|lancia|open|launch|start)\s+(.+?)\s*$", request)
        if not match:
            return None
        wanted = match.group(1).strip(" '\"")
        rows = self.search(wanted, 3)
        return rows[0] if rows else None


def link_applications(database, bin_dir=None, launcher_dir=None):
    bin_dir = Path(bin_dir or Path.home() / ".local/bin")
    launcher_dir = Path(launcher_dir or
                        Path(os.environ.get("XDG_DATA_HOME", Path.home() / ".local/share"))
                        / "za/launchers")
    bin_dir.mkdir(parents=True, exist_ok=True)
    created = skipped = 0
    rows = database.connection.execute("""
        SELECT name,identifier,source,launch_json FROM applications
        WHERE source IN ('desktop','appimage','flatpak')
        ORDER BY CASE source WHEN 'flatpak' THEN 0 WHEN 'appimage' THEN 1 ELSE 2 END,
                 name COLLATE NOCASE
    """)
    for row in rows:
        name = re.sub(r"[^a-z0-9._-]+", "-", row["name"].casefold()).strip("-.")
        if not name:
            name = re.sub(r"[^a-z0-9._-]+", "-", row["identifier"].casefold()).strip("-.")
        link = bin_dir / name
        if not name or link.exists() or link.is_symlink() or shutil.which(name):
            skipped += 1
            continue
        launch = json.loads(row["launch_json"])
        direct = Path(launch[0]) if len(launch) == 1 and Path(launch[0]).is_absolute() else None
        if direct and direct.is_file() and os.access(direct, os.X_OK):
            target = direct
        else:
            launcher_dir.mkdir(parents=True, exist_ok=True)
            target = launcher_dir / name
            target.write_text(f"#!/bin/sh\nexec {shlex.join(launch)} \"$@\"\n", encoding="utf-8")
            target.chmod(0o755)
        link.symlink_to(target)
        created += 1
    return {"created": created, "skipped": skipped, "bin_dir": str(bin_dir)}


def normalize_intent(request):
    text = request.strip().casefold()
    text = re.sub(r"(?:~|/)[^\s'\"]+", "{{path}}", text)
    text = re.sub(r"['\"][^'\"]+['\"]", "{{value}}", text)
    text = re.sub(r"\b\d+\b", "{{number}}", text)
    return " ".join(text.split())


SENSITIVE_KEY = re.compile(r"(?i)(password|passwd|token|api[_-]?key|secret|cookie|credential)")
SENSITIVE_TEXT = re.compile(
    r"(?i)(password|passwd|token|api[_-]?key|secret|cookie|credential)(\s*[:=]\s*)([^\s'\"]+)")


def redact_sensitive(text, environment=None):
    redacted = SENSITIVE_TEXT.sub(lambda m: f"{m.group(1)}{m.group(2)}<redacted>", text)
    for key, value in (environment or os.environ).items():
        if SENSITIVE_KEY.search(key) and value and len(value) >= 4:
            redacted = redacted.replace(value, "<redacted>")
    return redacted


def generalize_code(language, code):
    if language not in {"bash", "fish"} or "\n" in code.strip():
        return None
    try:
        argv = shlex.split(code)
    except ValueError:
        return None
    if len(argv) == 3 and Path(argv[0]).name in {"cp", "mv"}:
        return [argv[0], "{{source}}", "{{destination}}"]
    return None


def request_paths(request):
    return re.findall(r"(?:~|/)[^\s'\"]+", request)


@dataclasses.dataclass
class CodeProposal:
    explanation: str
    language: str
    code: str
    verification: str = "exit-code"
    risk: str = "normal"
    source: str = "model"
    skill_id: int | None = None
    skill_version: int | None = None
    generated_code: str = ""
    argv: list | None = None


class SkillStore:
    ALLOWED = {"proposed", "approved", "verified", "trusted", "failed", "revoked"}

    def __init__(self, database):
        self.db = database

    def ensure_builtins(self):
        definitions = {
            "launch-application": "Find and launch an installed native, desktop, Flatpak, or AppImage application.",
            "open-file": "Open a local file with an appropriate installed application.",
            "open-url": "Open an HTTP or HTTPS URL with the configured browser.",
            "manage-flatpak": "Inspect, install, or remove Flatpak applications with explicit approval.",
            "manage-apt-package": "Inspect or manage Debian packages with explicit approval.",
            "run-appimage": "Run an indexed AppImage safely by absolute path.",
            "inspect-systemd-service": "Inspect systemd service state and logs.",
            "inspect-logs": "Read and filter local logs without modifying them.",
            "copy-file": "Copy a file using explicit source and destination parameters.",
            "execute-python-script": "Run an approved Python script with a timeout.",
        }
        now = time.time()
        for name, description in definitions.items():
            self.db.connection.execute("""INSERT OR IGNORE INTO skills
              (name,description,intents_json,examples_json,parameters_json,prerequisites,risk,status,
               successes,failures,machine_hash,current_version,created_at,updated_at)
              VALUES(?,?,?,?,?,?,?,?,0,0,?,0,?,?)""",
              (name, description, json.dumps([name.replace("-", " ")]), "[]", "{}", "",
               "high" if name.startswith("manage-") else "normal", "proposed", machine_hash(), now, now))
        self._rebuild_fts()
        self.db.connection.commit()

    def relevant_descriptions(self, request, limit=3):
        if self.db.fts:
            safe = " ".join(re.findall(r"[\w.-]+", request.casefold(), re.UNICODE))
            if safe:
                with contextlib.suppress(sqlite3.OperationalError):
                    return [dict(row) for row in self.db.connection.execute("""SELECT s.* FROM skills_fts f
                      JOIN skills s ON s.id=f.skill_id WHERE skills_fts MATCH ? ORDER BY rank LIMIT ?""",
                      (safe, limit))]
        words = [word for word in re.findall(r"[\w.-]+", request.casefold()) if len(word) > 2]
        if not words:
            return []
        clauses = " OR ".join("description LIKE ? OR name LIKE ?" for _ in words)
        params = [value for word in words for value in (f"%{word}%", f"%{word}%")]
        return [dict(row) for row in self.db.connection.execute(
            f"SELECT * FROM skills WHERE {clauses} LIMIT ?", (*params, limit))]

    def create_candidate(self, request, proposal, approved_code):
        now, intent = time.time(), normalize_intent(request)
        name = f"procedure-{hashlib.sha256(intent.encode()).hexdigest()[:12]}"
        generated = redact_sensitive(proposal.generated_code or proposal.code)
        approved = redact_sensitive(approved_code)
        diff = "\n".join(difflib.unified_diff(generated.splitlines(), approved.splitlines(),
                                               fromfile="generated", tofile="approved", lineterm=""))
        row = self.db.connection.execute("SELECT id,current_version FROM skills WHERE name=?", (name,)).fetchone()
        if row:
            skill_id, version = row[0], row[1] + 1
            self.db.connection.execute("UPDATE skills SET current_version=?,status='approved',updated_at=? WHERE id=?",
                                       (version, now, skill_id))
        else:
            cursor = self.db.connection.execute("""INSERT INTO skills
              (name,description,intents_json,examples_json,parameters_json,prerequisites,risk,status,
               successes,failures,machine_hash,current_version,created_at,updated_at)
              VALUES(?,?,?,?,?,?,?,?,0,0,?,?,?,?)""",
              (name, proposal.explanation, json.dumps([intent]), json.dumps([request]), "{}", "",
               proposal.risk, "approved", machine_hash(), 1, now, now))
            skill_id, version = cursor.lastrowid, 1
        template = generalize_code(proposal.language, approved)
        self.db.connection.execute("""INSERT INTO skill_versions
          (skill_id,version,request,normalized_intent,generated_code,approved_code,diff_summary,
           language,template_json,template_status,verification,model,status,created_at)
           VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
          (skill_id, version, redact_sensitive(request), intent, generated, approved, diff,
           proposal.language, json.dumps(template) if template else None, "proposed",
           proposal.verification, MODEL, "approved", now))
        self._rebuild_fts()
        self.db.connection.commit()
        return skill_id, version

    def _rebuild_fts(self):
        if not self.db.fts:
            return
        self.db.connection.execute("DELETE FROM skills_fts")
        self.db.connection.execute("""INSERT INTO skills_fts
          SELECT id,name,description,intents_json,examples_json FROM skills""")

    def retrieve(self, request, limit=3):
        started = time.monotonic()
        intent = normalize_intent(request)
        rows = self.db.connection.execute("""SELECT s.*,v.request,v.approved_code,v.language,
          v.template_json,v.template_status,v.verification,v.version AS version FROM skills s JOIN skill_versions v
          ON v.skill_id=s.id AND v.version=s.current_version WHERE v.normalized_intent=?
          AND s.status IN ('verified','trusted') ORDER BY s.status='trusted' DESC,s.successes DESC LIMIT ?""",
          (intent, limit)).fetchall()
        if not rows and self.db.fts:
            safe = " ".join(re.findall(r"[\w.-]+", intent, re.UNICODE))
            if safe:
                with contextlib.suppress(sqlite3.OperationalError):
                    rows = self.db.connection.execute("""SELECT s.*,v.request,v.approved_code,v.language,
                      v.template_json,v.template_status,v.verification,v.version AS version FROM skills_fts f
                      JOIN skills s ON s.id=f.skill_id JOIN skill_versions v
                      ON v.skill_id=s.id AND v.version=s.current_version WHERE skills_fts MATCH ?
                      AND s.status IN ('verified','trusted') ORDER BY rank LIMIT ?""", (safe, limit)).fetchall()
        return [dict(row) for row in rows], time.monotonic() - started

    def proposal_from_skill(self, request, skill):
        code = skill["approved_code"]
        if skill.get("template_json") and skill.get("template_status") == "verified":
            template, paths = json.loads(skill["template_json"]), request_paths(request)
            if len(paths) < 2:
                return None
            argv = [paths[0] if item == "{{source}}" else paths[1]
                    if item == "{{destination}}" else item for item in template]
            code = shlex.join(argv)
        elif request.strip().casefold() != skill["request"].strip().casefold():
            return None
        return CodeProposal("Carico una procedura già verificata.", skill["language"], code,
                            skill["verification"], skill["risk"], "skill", skill["id"],
                            skill["version"], code)

    def record_outcome(self, skill_id, version, success):
        if not skill_id:
            return
        column = "successes" if success else "failures"
        self.db.connection.execute(f"UPDATE skills SET {column}={column}+1,updated_at=? WHERE id=?",
                                   (time.time(), skill_id))
        if success:
            row = self.db.connection.execute("SELECT successes FROM skills WHERE id=?", (skill_id,)).fetchone()
            status = "trusted" if row[0] >= 3 else "verified"
            self.db.connection.execute("UPDATE skills SET status=? WHERE id=?", (status, skill_id))
            self.db.connection.execute("UPDATE skill_versions SET status=? WHERE skill_id=? AND version=?",
                                       (status, skill_id, version))
            current = self.db.connection.execute("""SELECT template_json,request FROM skill_versions
              WHERE skill_id=? AND version=?""", (skill_id, version)).fetchone()
            if current and current["template_json"]:
                evidence = self.db.connection.execute("""SELECT 1 FROM skill_versions WHERE skill_id=?
                  AND version<>? AND template_json=? AND request<>? AND status IN ('verified','trusted') LIMIT 1""",
                  (skill_id, version, current["template_json"], current["request"])).fetchone()
                if evidence:
                    self.db.connection.execute("""UPDATE skill_versions SET template_status='verified'
                      WHERE skill_id=? AND version=?""", (skill_id, version))
        else:
            self.db.connection.execute("UPDATE skill_versions SET status='failed' WHERE skill_id=? AND version=?",
                                       (skill_id, version))
            previous = self.db.connection.execute("""SELECT version FROM skill_versions WHERE skill_id=?
              AND version<? AND status IN ('verified','trusted') ORDER BY version DESC LIMIT 1""",
              (skill_id, version)).fetchone()
            if previous:
                self.db.connection.execute("UPDATE skills SET current_version=?,status='verified' WHERE id=?",
                                           (previous[0], skill_id))
            else:
                self.db.connection.execute("UPDATE skills SET status='failed' WHERE id=?", (skill_id,))
        self.db.connection.commit()

    def list(self):
        return self.db.connection.execute("SELECT * FROM skills ORDER BY updated_at DESC").fetchall()

    def get(self, name):
        return self.db.connection.execute("SELECT * FROM skills WHERE name=?", (name,)).fetchone()

    def revoke(self, name, delete=False):
        if delete:
            self.db.connection.execute("DELETE FROM skills WHERE name=?", (name,))
        else:
            self.db.connection.execute("UPDATE skills SET status='revoked',updated_at=? WHERE name=?",
                                       (time.time(), name))
        self._rebuild_fts()
        self.db.connection.commit()


class ModelEngine:
    def __init__(self, config):
        self.config, self.tokenizer, self.model = config, None, None
        self.load_seconds = None
        self.last_metrics = {}

    def cache_present(self):
        snapshots = self.config.model_cache / f"models--{MODEL.replace('/', '--')}" / "snapshots"
        if not snapshots.exists():
            return False
        for snapshot in snapshots.iterdir():
            has_weights = ((snapshot / "model.safetensors").exists()
                           or (snapshot / "model.safetensors.index.json").exists())
            if (snapshot / "config.json").exists() and has_weights:
                return True
        return False

    def load(self):
        if self.model is not None:
            return self.tokenizer, self.model
        import torch
        from transformers import AutoModelForCausalLM, AutoTokenizer
        cached = self.cache_present()
        if cached:
            show_status("◆", "Carico il modello dalla cache Za…")
        else:
            print(terminal_style("╭──────────────────────╮", ANSI_MAGENTA))
            print(terminal_style("│ ↓  MODEL DOWNLOAD  ↓ │", ANSI_YELLOW))
            print(terminal_style("╰──────────────────────╯", ANSI_BLUE))
            show_status("◆", f"Scarico {MODEL}…", ANSI_GREEN)
            show_status("→", str(self.config.model_cache), ANSI_CYAN)
        started = time.monotonic()
        self.config.model_cache.mkdir(parents=True, exist_ok=True)
        self.tokenizer = AutoTokenizer.from_pretrained(
            MODEL, cache_dir=self.config.model_cache, local_files_only=cached)
        kwargs = dict(cache_dir=self.config.model_cache, device_map="auto", low_cpu_mem_usage=True,
                      torch_dtype=torch.float16 if torch.cuda.is_available() else torch.bfloat16,
                      local_files_only=cached)
        try:
            self.model = AutoModelForCausalLM.from_pretrained(MODEL, attn_implementation="sdpa", **kwargs)
        except (TypeError, ValueError, RuntimeError):
            self.model = AutoModelForCausalLM.from_pretrained(MODEL, **kwargs)
        self.model.eval()
        self.load_seconds = time.monotonic() - started
        return self.tokenizer, self.model

    def generate(self, messages):
        import torch
        from transformers import TextIteratorStreamer
        tokenizer, model = self.load()
        inputs = tokenizer.apply_chat_template(
            messages, add_generation_prompt=True, return_tensors="pt",
            return_dict=True, tokenize=True)
        if hasattr(inputs, "to"):
            inputs = inputs.to(model.device)
        streamer = TextIteratorStreamer(tokenizer, skip_prompt=True, skip_special_tokens=True)
        errors, chunks = [], []
        started, first_token = time.monotonic(), [None]

        def work():
            try:
                with torch.inference_mode():
                    model.generate(**inputs, streamer=streamer,
                                   max_new_tokens=self.config.max_new_tokens,
                                   do_sample=False, repetition_penalty=self.config.repetition_penalty,
                                   use_cache=True, pad_token_id=tokenizer.eos_token_id)
            except Exception as error:
                errors.append(error)
                streamer.end()

        worker = threading.Thread(target=work)
        worker.start()
        if sys.stdout.isatty():
            print(terminal_style("╭─ sto elaborando", ANSI_GRAY))
        for chunk in streamer:
            if first_token[0] is None:
                first_token[0] = time.monotonic()
            chunks.append(chunk)
        worker.join()
        if sys.stdout.isatty():
            print(terminal_style("\n╰─ proposta pronta", ANSI_GRAY))
        if errors:
            raise errors[0]
        elapsed = time.monotonic() - started
        tokens = len(tokenizer.encode("".join(chunks), add_special_tokens=False))
        self.last_metrics = {"generation_seconds": elapsed, "first_token_seconds":
                             (first_token[0] - started if first_token[0] else None),
                             "tokens": tokens, "tokens_per_second": tokens / elapsed if elapsed else 0}
        return "".join(chunks)


def parse_model_output(text):
    candidates = []
    fenced = re.search(r"```json\s*(.*?)```", text, re.I | re.S)
    if fenced:
        candidates.append(fenced.group(1))
    candidates.append(text)
    for candidate in candidates:
        decoder = json.JSONDecoder()
        for start in (match.start() for match in re.finditer(r"\{", candidate)):
            try:
                value, _ = decoder.raw_decode(candidate[start:])
            except json.JSONDecodeError:
                continue
            if isinstance(value, dict) and value.get("language") in LANGUAGE_ALIASES and isinstance(value.get("code"), str):
                language = LANGUAGE_ALIASES[value["language"]]
                return CodeProposal(str(value.get("explanation", "Proposta generata.")), language,
                                    value["code"].strip(), str(value.get("verification", "exit-code")),
                                    str(value.get("risk", "normal")), generated_code=value["code"].strip())
    extracted = extract_code(text)
    if extracted:
        language, code = extracted
        return CodeProposal("Il modello ha restituito un blocco di codice non strutturato; controllalo con attenzione.",
                            language, code, risk="review", generated_code=code)
    return None


def extract_code(text):
    match = re.search(r"```([A-Za-z0-9_+-]+)[^\S\r\n]*\r?\n(.*?)```", text, re.S)
    if not match or match.group(1).lower() not in LANGUAGE_ALIASES:
        return None
    return LANGUAGE_ALIASES[match.group(1).lower()], match.group(2).strip()


class Executor:
    def __init__(self, timeout=120, output_limit=OUTPUT_LIMIT):
        self.timeout, self.output_limit = timeout, output_limit

    @staticmethod
    def risk(code):
        high = re.compile(r"(?i)(\bsudo\b|\brm\s|\bapt(?:-get)?\s+(?:install|remove|purge)|"
                          r"\bflatpak\s+(?:install|uninstall)|\bsystemctl\s+(?:start|stop|restart|enable|disable)|"
                          r"\b(?:kill|pkill|killall)\b|(?:^|\s)>\s*/(?:etc|usr|boot)/|"
                          r"\b(?:unlink|rmtree|remove)\s*\(|\bwrite_(?:text|bytes)\s*\(|"
                          r"\bopen\s*\([^)]*,\s*['\"](?:w|a|x)|\bshutil\.(?:copy|move)\s*\()")
        if high.search(code):
            return "high"
        if "\n" not in code.strip():
            with contextlib.suppress(ValueError, OSError):
                argv = shlex.split(code)
                if len(argv) >= 3 and Path(argv[0]).name in {"cp", "mv", "install"}:
                    if Path(argv[-1]).expanduser().exists():
                        return "high"
        return "normal"

    def run(self, proposal, cwd=None):
        tmp_file = None
        if proposal.argv:
            command = proposal.argv
        else:
            interpreter, suffix = INTERPRETERS[proposal.language]
            handle = tempfile.NamedTemporaryFile(mode="w", suffix=suffix, delete=False, encoding="utf-8")
            with handle:
                handle.write(proposal.code)
            tmp_file = handle.name
            command = [interpreter, tmp_file]
        try:
            process = subprocess.Popen(command, cwd=cwd or os.getcwd(), stdout=subprocess.PIPE,
                                       stderr=subprocess.PIPE, text=True, start_new_session=True)
            try:
                stdout, stderr = process.communicate(timeout=self.timeout)
            except subprocess.TimeoutExpired:
                os.killpg(process.pid, signal.SIGTERM)
                try:
                    stdout, stderr = process.communicate(timeout=3)
                except subprocess.TimeoutExpired:
                    os.killpg(process.pid, signal.SIGKILL)
                    stdout, stderr = process.communicate()
                stderr += f"\nZa: timeout after {self.timeout}s"
                process.returncode = 124
            return subprocess.CompletedProcess(command, process.returncode,
                                               stdout[-self.output_limit:], stderr[-self.output_limit:])
        finally:
            if tmp_file:
                with contextlib.suppress(OSError):
                    Path(tmp_file).unlink()

    def start(self, proposal, cwd=None):
        if proposal.argv:
            command = proposal.argv
        else:
            interpreter, _ = INTERPRETERS[proposal.language]
            command = [interpreter, "-c", proposal.code]
        process = subprocess.Popen(command, cwd=cwd or os.getcwd(), stdin=subprocess.DEVNULL,
                                   stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                   start_new_session=True)
        process._za_stdout = b""
        process._za_stderr = b""

        def capture(stream, attribute):
            while True:
                chunk = stream.read1(4096)
                if not chunk:
                    break
                current = getattr(process, attribute)
                setattr(process, attribute, (current + chunk)[-self.output_limit:])
            stream.close()

        process._za_output_threads = [
            threading.Thread(target=capture, args=(process.stdout, "_za_stdout"), daemon=True),
            threading.Thread(target=capture, args=(process.stderr, "_za_stderr"), daemon=True),
        ]
        for thread in process._za_output_threads:
            thread.start()
        threading.Thread(target=process.wait, daemon=True).start()
        return process


class Validator:
    def validate(self, proposal, result):
        if result.returncode != 0:
            return False, f"exit-code:{result.returncode}"
        command = proposal.argv
        if not command and proposal.language in {"bash", "fish"}:
            with contextlib.suppress(ValueError):
                command = shlex.split(proposal.code)
        if command and Path(command[0]).name in {"cp", "mv", "touch", "mkdir"} and len(command) >= 2:
            target = Path(command[-1]).expanduser()
            return target.exists(), f"path-exists:{target}"
        if command and command[:2] == ["flatpak", "install"] and len(command) > 2:
            check = subprocess.run(["flatpak", "info", command[-1]], capture_output=True,
                                   text=True, timeout=10, check=False)
            return check.returncode == 0, "flatpak-info"
        return True, "exit-code"


def concise_diff(original, approved):
    if original == approved:
        return "nessuna modifica"
    return f"{sum(1 for _ in difflib.ndiff(original.splitlines(), approved.splitlines()))} righe confrontate"


class ZaAgent:
    def __init__(self, config, database=None, engine=None):
        self.config = config
        self.db = database or SystemDatabase(config.cache_dir / "system.sqlite")
        self.scanner = SystemScanner(config, self.db)
        self.resolver = ApplicationResolver(self.db)
        self.skills = SkillStore(self.db)
        self.skills.ensure_builtins()
        self.engine = engine or ModelEngine(config)
        self.executor, self.validator = Executor(config.timeout), Validator()
        self._import_legacy_history()

    def _import_legacy_history(self):
        if self.db.metadata("legacy_imported"):
            return
        path = Path(os.environ.get("XDG_STATE_HOME", Path.home() / ".local/state")) / "za/successes.json"
        try:
            entries = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            entries = []
        for item in entries if isinstance(entries, list) else []:
            if not all(key in item for key in ("request", "language", "code")):
                continue
            proposal = CodeProposal("Procedura importata dalla cronologia Za.", item["language"], item["code"],
                                    generated_code=item["code"])
            skill_id, version = self.skills.create_candidate(item["request"], proposal, item["code"])
            self.skills.record_outcome(skill_id, version, True)
        self.db.set_metadata("legacy_imported", "1")

    def system_context(self, applications, skills):
        app_context = [{"name": a["name"], "source": a["source"],
                        "launch": json.loads(a["launch_json"])} for a in applications[:3]]
        skill_context = [{"name": s["name"], "description": s["description"],
                          "status": s["status"]} for s in skills[:3]]
        return {"cwd": os.getcwd(), "applications": app_context, "skills": skill_context}

    def propose(self, request):
        show_status("⌕", "Cerco procedure collaudate pertinenti…", ANSI_CYAN)
        skills, search_seconds = self.skills.retrieve(request)
        for skill in skills:
            proposal = self.skills.proposal_from_skill(request, skill)
            if proposal:
                show_status("↳", "Carico la procedura già verificata.", ANSI_GREEN)
                return proposal, {"skill_search_seconds": search_seconds}
        app = self.resolver.resolve_request(request)
        if app:
            show_status("✓", f"Ho trovato {app['name']} come applicazione {app['source']}.", ANSI_GREEN)
            argv = json.loads(app["launch_json"])
            code = shlex.join(argv)
            return CodeProposal(f"Avvierò {app['name']} usando il metodo registrato dal sistema.",
                                "bash", code, "process-started", "normal", "resolver",
                                generated_code=code, argv=argv), {"skill_search_seconds": search_seconds}
        show_status("✦", "Non ho una procedura verificata: preparo una nuova proposta…", ANSI_MAGENTA)
        related_apps = self.resolver.search(" ".join(re.findall(r"[\w.-]+", request)[-3:]), 3)
        context = self.system_context(related_apps, self.skills.relevant_descriptions(request))
        system = """Sei Za, un micro-agente Linux locale specializzato esclusivamente in operazioni
su file, directory, filesystem, dispositivi montati e spazio disco. Rispondi nella lingua dell'utente.
Spiega brevemente cosa hai capito e cosa proponi. Non inventare percorsi, applicazioni o comandi:
usa solo richiesta e contesto forniti. Non eseguire nulla. Restituisci esclusivamente JSON valido:
{"explanation":"...","language":"python|bash|fish","code":"...","verification":"...","risk":"normal|high"}.
Il codice deve essere ripetibile, usare argv/subprocess senza shell quando possibile e comunicare errori utili."""
        user = f"Contesto macchina pertinente:\n{json.dumps(context, ensure_ascii=False)}\n\nRichiesta: {request}"
        raw = self.engine.generate([{"role": "system", "content": system},
                                    {"role": "user", "content": user}])
        proposal = parse_model_output(raw)
        if proposal:
            proposal.generated_code = proposal.code
        return proposal, {"skill_search_seconds": search_seconds, **self.engine.last_metrics}

    def execute_approved(self, request, proposal, approved_code):
        proposal.code = approved_code
        proposal.risk = "high" if Executor.risk(approved_code) == "high" else proposal.risk
        if proposal.argv and approved_code != proposal.generated_code:
            proposal.argv = None
        skill_id, version = proposal.skill_id, proposal.skill_version
        if not skill_id or approved_code != proposal.generated_code:
            skill_id, version = self.skills.create_candidate(request, proposal, approved_code)
        process = self.executor.start(proposal)
        cursor = self.db.connection.execute("""INSERT INTO executions
          (skill_id,skill_version,request,normalized_intent,generated_code,approved_code,
           parameters_json,exit_code,stdout,stderr,semantic_ok,result,model,created_at)
          VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
          (skill_id, version, redact_sensitive(request), normalize_intent(request),
           redact_sensitive(proposal.generated_code), redact_sensitive(approved_code),
           json.dumps({"paths": request_paths(request)}, ensure_ascii=False),
           None, "", "", 0, "process-started", MODEL, time.time()))
        self.db.connection.commit()
        return process, cursor.lastrowid, skill_id, version

    def record_feedback(self, execution_id, skill_id, version, success, exit_code=None):
        self.skills.record_outcome(skill_id, version, success)
        value = "success" if success else "failure"
        self.db.connection.execute(
            "UPDATE executions SET exit_code=?,semantic_ok=?,result=? WHERE id=?",
            (exit_code, int(success), f"user-feedback:{value}", execution_id))
        self.db.connection.execute("""INSERT INTO feedback(execution_id,kind,value,created_at)
          VALUES(?,?,?,?)""", (execution_id, "execution-result", value, time.time()))
        self.db.connection.commit()


def show_code(proposal, code=None):
    if isinstance(proposal, str):
        proposal = CodeProposal("", proposal, code or "")
    print(f"\n{terminal_style('✦', ANSI_CYAN)}  {terminal_style('Codice proposto', ANSI_BOLD)}  "
          f"{terminal_style(proposal.language, ANSI_DIM)}")
    if proposal.explanation:
        print(terminal_style(f"│ {proposal.explanation}", ANSI_CYAN))
    for line in proposal.code.splitlines():
        print(f"{terminal_style('│', ANSI_DIM)} {terminal_style(line, ANSI_YELLOW)}")


def show_result(result, success, verification):
    print(f"\n{terminal_style('✦', ANSI_CYAN)}  {terminal_style('Risultato', ANSI_BOLD)}")
    if result.stdout:
        print(result.stdout, end="" if result.stdout.endswith("\n") else "\n")
    if result.stderr and not success:
        print(result.stderr, end="" if result.stderr.endswith("\n") else "\n")
    if success:
        show_status("✓", f"Procedura riuscita e memorizzata ({verification}).", ANSI_GREEN)
    else:
        show_status("✕", f"La verifica non ha confermato il risultato ({verification}).", ANSI_RED)


def process_output(process, channel):
    if process.poll() is not None:
        for thread in vars(process).get("_za_output_threads", ()):
            thread.join(timeout=0.1)
    value = vars(process).get(f"_za_{channel}", b"")
    return value.decode("utf-8", errors="replace") if isinstance(value, bytes) else value


def format_output_lines(output, width):
    clean = ANSI_ESCAPE.sub("", output or "").expandtabs(4)
    lines = []
    for line in clean.splitlines() or [""]:
        lines.extend(textwrap.wrap(line, width=max(1, width), replace_whitespace=False,
                                   drop_whitespace=False, break_long_words=True,
                                   break_on_hyphens=False) or [""])
    return lines


def process_status(process):
    exit_code = process.poll()
    if exit_code is None:
        return f"In esecuzione · PID {process.pid}", ANSI_CYAN
    color = ANSI_GREEN if exit_code == 0 else ANSI_RED
    return f"Terminato · codice {exit_code}", color


def show_output_panels(process, stdout_open=False, stderr_open=False):
    status, status_color = process_status(process)
    print(f"\n{terminal_style('✦', ANSI_CYAN)}  {terminal_style('Risultato esecuzione', ANSI_BOLD)}"
          f"  {terminal_style(status, status_color)}")
    print(terminal_separator())
    print(terminal_style("Output", ANSI_BOLD))
    if stdout_open:
        output = process_output(process, "stdout")
        if output:
            print(output, end="" if output.endswith("\n") else "\n")
        else:
            print(terminal_style("(nessun output)", ANSI_DIM))
    print()
    print(terminal_style("Errori", ANSI_RED, ANSI_BOLD))
    if stderr_open:
        error = process_output(process, "stderr")
        if error:
            rendered = terminal_style(error, ANSI_RED)
            print(rendered, end="" if error.endswith("\n") else "\n")
        else:
            print(terminal_style("(nessun errore)", ANSI_DIM))
    print(terminal_separator())


def output_tab_ranges(labels=None):
    labels = labels or {"stdout": "Output", "stderr": "Errori"}
    ranges = []
    start = 0
    for channel in ("stdout", "stderr"):
        end = start + len(labels[channel]) + 2
        ranges.append((channel, start, end))
        start = end + 1
    return ranges


def clicked_output_tab(x, y, ranges=None):
    if y != 0:
        return None
    for channel, start, end in ranges or output_tab_ranges():
        if start <= x < end:
            return channel
    return None


def _screen_add(screen, y, x, text, attribute=0):
    height, width = screen.getmaxyx()
    if y < 0 or x < 0 or y >= height or x >= width:
        return
    with contextlib.suppress(curses.error):
        screen.addnstr(y, x, text, width - x, attribute)


def _output_tabs(screen, process):
    with contextlib.suppress(curses.error):
        curses.curs_set(0)
    with contextlib.suppress(curses.error):
        curses.start_color()
        curses.use_default_colors()
        curses.init_pair(1, curses.COLOR_RED, -1)
    curses.mousemask(curses.ALL_MOUSE_EVENTS)
    curses.mouseinterval(0)
    screen.keypad(True)
    screen.timeout(200)
    active, scroll, follow = "stdout", 0, True

    while True:
        screen.erase()
        height, width = screen.getmaxyx()
        body_height = max(1, height - 7)
        status, status_color = process_status(process)
        status_attribute = (curses.color_pair(1) if status_color == ANSI_RED
                            else curses.A_BOLD)
        title = "ZA · Risultato esecuzione"
        _screen_add(screen, 0, 0, title, curses.A_BOLD)
        if len(title) + len(status) + 2 < width:
            _screen_add(screen, 0, width - len(status), status, status_attribute)
        _screen_add(screen, 1, 0, "─" * width, curses.A_DIM)

        labels = {}
        for channel, name in (("stdout", "Output"), ("stderr", "Errori")):
            output = process_output(process, channel)
            count = len(output.splitlines()) if output else 0
            amount = "vuoto" if not count else "1 riga" if count == 1 else f"{count} righe"
            labels[channel] = f"{name} · {amount}"
        tabs = output_tab_ranges(labels)
        for channel, start, _ in tabs:
            attribute = curses.A_BOLD
            if channel == active:
                attribute |= curses.A_REVERSE
            if channel == "stderr":
                attribute |= curses.color_pair(1)
            _screen_add(screen, 2, start, f" {labels[channel]} ", attribute)
        _screen_add(screen, 3, 0, "─" * width, curses.A_DIM)

        output = process_output(process, active)
        if output:
            lines = format_output_lines(output, width - 2)
        else:
            lines = ["(in attesa di output)" if process.poll() is None else
                     "(nessun output)" if active == "stdout" else "(nessun errore)"]
        max_scroll = max(0, len(lines) - body_height)
        scroll = max_scroll if follow else min(scroll, max_scroll)
        output_attribute = curses.color_pair(1) if active == "stderr" else 0
        for row, line in enumerate(lines[scroll:scroll + body_height], start=4):
            _screen_add(screen, row, 2, line, output_attribute)

        _screen_add(screen, height - 3, 0, "─" * width, curses.A_DIM)
        _screen_add(screen, height - 2, 0,
                    "←→ cambia sezione · ↑↓ scorri · PgUp/PgDn pagina", curses.A_DIM)
        _screen_add(screen, height - 1, 0,
                    "Esito: [Invio/S] riuscita · [N] non riuscita · [Esc] non registrare",
                    curses.A_BOLD)
        screen.refresh()
        key = screen.getch()

        if key == curses.KEY_MOUSE:
            with contextlib.suppress(curses.error):
                _, x, y, _, state = curses.getmouse()
                click = (getattr(curses, "BUTTON1_CLICKED", 0)
                         | getattr(curses, "BUTTON1_PRESSED", 0))
                if state & click:
                    selected = clicked_output_tab(x, y - 2, tabs)
                    if selected:
                        active, scroll, follow = selected, 0, True
                elif state & getattr(curses, "BUTTON4_PRESSED", 0):
                    scroll = max(0, scroll - 3)
                    follow = False
                elif state & getattr(curses, "BUTTON5_PRESSED", 0):
                    scroll = min(max_scroll, scroll + 3)
                    follow = scroll == max_scroll
            continue
        if key in (ord("\n"), ord("\r"), curses.KEY_ENTER, ord("s"), ord("S"), ord("y"), ord("Y")):
            return True
        if key in (ord("n"), ord("N")):
            return False
        if key in (3, 27, ord("q"), ord("Q")):
            return None
        if key in (curses.KEY_LEFT, curses.KEY_RIGHT, ord("\t")):
            active = "stderr" if active == "stdout" else "stdout"
            scroll, follow = 0, True
        elif key == ord("o"):
            active, scroll, follow = "stdout", 0, True
        elif key == ord("e"):
            active, scroll, follow = "stderr", 0, True
        elif key == curses.KEY_UP:
            scroll = max(0, scroll - 1)
            follow = False
        elif key == curses.KEY_DOWN:
            scroll = min(max_scroll, scroll + 1)
            follow = scroll == max_scroll
        elif key == curses.KEY_PPAGE:
            scroll = max(0, scroll - body_height)
            follow = False
        elif key == curses.KEY_NPAGE:
            scroll = min(max_scroll, scroll + body_height)
            follow = scroll == max_scroll
        elif key == curses.KEY_HOME:
            scroll, follow = 0, False
        elif key == curses.KEY_END:
            scroll, follow = max_scroll, True


def _plain_output_feedback(process):
    show_output_panels(process, True, True)
    while True:
        try:
            answer = input("Esito — [Invio/s] riuscita · [n] non riuscita: ")
        except (EOFError, KeyboardInterrupt):
            print()
            return None
        success = feedback_action(answer)
        if success is not None:
            return success
        show_status("!", "Feedback non valido: rispondi s oppure n.", ANSI_YELLOW)


def output_feedback(process):
    if not sys.stdin.isatty() or not sys.stdout.isatty():
        return _plain_output_feedback(process)
    try:
        return curses.wrapper(_output_tabs, process)
    except curses.error:
        return _plain_output_feedback(process)


def edit_code(language, code):
    editor = os.environ.get("VISUAL") or os.environ.get("EDITOR") or "nano"
    suffix = INTERPRETERS[language][1]
    with tempfile.NamedTemporaryFile(mode="w", suffix=suffix, delete=False, encoding="utf-8") as file:
        file.write(code)
        path = Path(file.name)
    try:
        result = subprocess.run([*shlex.split(editor), str(path)])
        return path.read_text(encoding="utf-8").strip() if result.returncode == 0 else code
    finally:
        with contextlib.suppress(OSError):
            path.unlink()


def confirmation_action(answer):
    return {"": "execute", "y": "execute", "e": "edit", "n": "cancel"}.get(
        answer.strip().lower(), "invalid")


def feedback_action(answer):
    normalized = answer.strip().casefold()
    if normalized in {"", "s", "si", "sì", "y", "yes"}:
        return True
    if normalized in {"n", "no"}:
        return False
    return None


# Compatibility helpers retained for callers of the original single-file API.
_COMPAT_ENGINE = None


def load_model():
    global _COMPAT_ENGINE
    if _COMPAT_ENGINE is None:
        _COMPAT_ENGINE = ModelEngine(Config.create())
    return _COMPAT_ENGINE.load()


def generate_stream(tokenizer, model, inputs):
    import torch
    from transformers import TextIteratorStreamer
    streamer = TextIteratorStreamer(tokenizer, skip_prompt=True, skip_special_tokens=True)
    errors, chunks = [], []

    def work():
        try:
            with torch.inference_mode():
                model.generate(**inputs, streamer=streamer, max_new_tokens=768,
                               do_sample=False, repetition_penalty=1.05, use_cache=True,
                               pad_token_id=tokenizer.eos_token_id)
        except Exception as error:
            errors.append(error); streamer.end()
    worker = threading.Thread(target=work); worker.start()
    for chunk in streamer:
        chunks.append(chunk)
    worker.join()
    if errors:
        raise errors[0]
    return "".join(chunks)


def ask_model(prompt):
    tokenizer, model = load_model()
    inputs = tokenizer(prompt, return_tensors="pt")
    if hasattr(inputs, "to"):
        inputs = inputs.to(model.device)
    return generate_stream(tokenizer, model, inputs)


def run_code(language, code):
    return Executor().run(CodeProposal("", language, code))


def build_prompt(user_request, successful_commands=None):
    examples = ""
    if successful_commands:
        examples = "\n\nExamples previously run successfully:\n" + "\n\n".join(
            f"Request: {item['request']}\n```{item['language']}\n{item['code']}\n```"
            for item in successful_commands[-3:])
    return ("Act as a Linux operations assistant. Return one executable Python, Bash, or Fish "
            f"Markdown code block. Do not invent paths.\n{examples}\nRequest: {user_request}")


def build_retry_prompt(user_request, language, code, result):
    return (f"The script did not complete the request. Fix it.\nOriginal request: {user_request}\n"
            f"Language: {language}\nCode:\n```{language}\n{code}\n```\nExit code: {result.returncode}\n"
            f"Output:\n{result.stdout}\nError:\n{result.stderr}")


def load_successes(path):
    try:
        value = json.loads(Path(path).read_text(encoding="utf-8"))
        return value if isinstance(value, list) else []
    except (OSError, json.JSONDecodeError):
        return []


def remember_success(commands, user_request, language, code, path):
    commands[:] = [item for item in commands if item.get("request", "").strip().casefold()
                   != user_request.strip().casefold()]
    commands.append({"request": user_request, "language": language, "code": code})
    Path(path).parent.mkdir(parents=True, exist_ok=True)
    Path(path).write_text(json.dumps(commands, ensure_ascii=False, indent=2), encoding="utf-8")


def recall_success(commands, user_request):
    wanted = user_request.strip().casefold()
    for item in reversed(commands):
        if item.get("request", "").strip().casefold() == wanted:
            return item["language"], item["code"]
    return None


def interactive(agent):
    print(terminal_header())
    print(terminal_style("Scrivi una richiesta · ↑/Ctrl-R cronologia · exit/quit per uscire", ANSI_DIM))
    print(terminal_separator())
    readline.set_auto_history(True)
    show_status("⌁", "Aggiorno rapidamente la mappa delle applicazioni…", ANSI_CYAN)
    scan = agent.scanner.scan()
    if not scan["cached"]:
        show_status("✓", f"Mappa aggiornata in {scan['seconds']:.2f}s.", ANSI_GREEN)
    while True:
        try:
            request = input(terminal_prompt()).strip()
        except EOFError:
            print()
            return
        except KeyboardInterrupt:
            print()
            continue
        if request.casefold() in {"exit", "quit"}:
            return
        if not request:
            continue
        try:
            proposal, _ = agent.propose(request)
        except (ImportError, OSError, RuntimeError, ValueError) as error:
            show_status("✕", f"Non posso generare la proposta: {error}", ANSI_RED)
            continue
        if not proposal:
            show_status("!", "La risposta non contiene una proposta strutturata sicura; non eseguo nulla.", ANSI_YELLOW)
            continue
        while True:
            show_status("→", "Ti mostro il codice prima dell’esecuzione.", ANSI_CYAN)
            show_code(proposal)
            high_risk = Executor.risk(proposal.code) == "high" or proposal.risk == "high"
            prompt = ("\nRISCHIO ELEVATO — digita 'approve' per eseguire · e modifica · n annulla: "
                      if high_risk else "\n[Invio] esegui · e modifica · n annulla: ")
            try:
                answer = input(prompt)
            except (EOFError, KeyboardInterrupt):
                print()
                answer = "n"
            if high_risk:
                action = "execute" if answer.strip().casefold() == "approve" else (
                    "edit" if answer.strip().casefold() == "e" else "cancel" if answer.strip().casefold() == "n" else "invalid")
            else:
                action = confirmation_action(answer)
            if action == "edit":
                proposal.code = edit_code(proposal.language, proposal.code)
                continue
            if action == "invalid":
                show_status("!", "Scelta non valida.", ANSI_YELLOW)
                continue
            if action == "cancel":
                show_status("—", "Esecuzione annullata: nulla è stato avviato.", ANSI_DIM)
                break
            show_status("▶", "Avvio in background esclusivamente il codice approvato…", ANSI_MAGENTA)
            process, execution_id, skill_id, version = agent.execute_approved(
                request, proposal, proposal.code)
            show_status("✓", f"Script avviato in background (&), PID {process.pid}.", ANSI_GREEN)
            success = output_feedback(process)
            if success is None:
                show_status("!", "Feedback non registrato.", ANSI_YELLOW)
                break
            agent.record_feedback(execution_id, skill_id, version, success, process.poll())
            if success:
                show_status("✓", "Feedback registrato: procedura riuscita.", ANSI_GREEN)
            else:
                show_status("✕", "Feedback registrato: procedura non riuscita.", ANSI_RED)
            break
        print(f"\n{terminal_separator()}\n")


def run_self_tests():
    import unittest
    import types
    from unittest.mock import Mock, patch

    class Tests(unittest.TestCase):
        def setUp(self):
            self.temp = tempfile.TemporaryDirectory()
            self.root = Path(self.temp.name)
            self.config = Config(self.root / "machine", self.root / "models",
                                 appimage_dirs=(self.root / "apps",))
            self.db = SystemDatabase(self.config.cache_dir / "system.sqlite")

        def tearDown(self):
            self.db.close()
            self.temp.cleanup()

        def test_01_schema_and_reopen(self):
            self.assertEqual(self.db.connection.execute("SELECT version FROM schema_info").fetchone()[0], SCHEMA_VERSION)
            self.assertTrue(self.db.connection.execute("SELECT name FROM sqlite_master WHERE name='skills'").fetchone())

        def test_02_desktop_parser(self):
            self.assertEqual(desktop_exec_to_argv('app --name "%c" %F %%', "Hello", "/x.desktop"),
                             ["app", "--name", "Hello", "%"])
            self.assertEqual(desktop_exec_to_argv("unterminated '"), [])

        def test_03_flatpak_scan(self):
            result = subprocess.CompletedProcess([], 0, "org.gimp.GIMP\tGIMP\tstable\tuser\n", "")
            scanner = SystemScanner(self.config, self.db, runner=Mock(return_value=result))
            with patch("shutil.which", return_value="/usr/bin/flatpak"):
                self.assertEqual(scanner.scan_flatpak(), 1)
            row = self.db.connection.execute("SELECT launch_json FROM applications WHERE source='flatpak'").fetchone()
            self.assertEqual(json.loads(row[0]), ["/usr/bin/flatpak", "run", "org.gimp.GIMP"])

        def test_04_appimage_scan(self):
            app_dir = self.root / "apps"; app_dir.mkdir()
            app = app_dir / "My App.AppImage"; app.write_bytes(b"app"); app.chmod(0o755)
            self.assertEqual(SystemScanner(self.config, self.db).scan_appimages(), 1)
            metadata = json.loads(self.db.connection.execute("SELECT metadata_json FROM applications").fetchone()[0])
            self.assertTrue(metadata["executable"])

        def test_05_exact_alias_and_search(self):
            self.db.upsert_application({"source":"native","identifier":"paint","name":"Paint",
                                        "description":"image editor","launch":["paint"],"aliases":["draw"]})
            self.db.connection.commit(); self.db.rebuild_application_fts()
            resolver = ApplicationResolver(self.db)
            self.assertEqual(resolver.search("Paint")[0]["identifier"], "paint")
            self.assertEqual(resolver.search("draw")[0]["identifier"], "paint")
            self.assertEqual(resolver.search("image")[0]["identifier"], "paint")

        def test_06_candidate_and_approved_edit(self):
            store = SkillStore(self.db)
            proposal = CodeProposal("copy", "bash", "cp /a /b", generated_code="cp /a /wrong")
            skill_id, version = store.create_candidate("copy /a /b", proposal, proposal.code)
            row = self.db.connection.execute("SELECT * FROM skill_versions WHERE skill_id=?", (skill_id,)).fetchone()
            self.assertEqual(row["generated_code"], "cp /a /wrong")
            self.assertEqual(row["approved_code"], "cp /a /b")
            self.assertTrue(row["diff_summary"])
            self.assertEqual(row["status"], "approved")

        def test_07_verified_transition_and_reuse(self):
            store = SkillStore(self.db)
            proposal = CodeProposal("say hello", "bash", "echo hello", generated_code="echo hello")
            skill_id, version = store.create_candidate("say hello", proposal, proposal.code)
            store.record_outcome(skill_id, version, True)
            self.assertEqual(store.get(f"procedure-{hashlib.sha256(normalize_intent('say hello').encode()).hexdigest()[:12]}")["status"], "verified")
            skills, _ = store.retrieve("say hello")
            self.assertEqual(store.proposal_from_skill("say hello", skills[0]).code, "echo hello")

        def test_08_failure_recorded_without_good_version_loss(self):
            store = SkillStore(self.db)
            first = CodeProposal("test", "bash", "true", generated_code="true")
            skill_id, version = store.create_candidate("test it", first, "true")
            store.record_outcome(skill_id, version, True)
            _, bad_version = store.create_candidate("test it", first, "false")
            store.record_outcome(skill_id, bad_version, False)
            row = self.db.connection.execute("SELECT current_version,status,failures FROM skills WHERE id=?", (skill_id,)).fetchone()
            self.assertEqual((row[0], row[1], row[2]), (version, "verified", 1))

        def test_09_no_execution_without_explicit_call(self):
            agent = Mock()
            agent.scanner.scan.return_value = {"cached": True, "seconds": 0}
            agent.propose.return_value = (CodeProposal("proposal", "bash", "echo safe"), {})
            with patch("builtins.input", side_effect=["do it", "n", "quit"]), \
                 patch("sys.stdout", new=Mock(isatty=Mock(return_value=False))):
                interactive(agent)
            agent.execute_approved.assert_not_called()

        def test_10_redaction(self):
            self.assertNotIn("abcd1234", redact_sensitive("token=abcd1234 x", {"API_KEY":"abcd1234"}))
            self.assertIn("<redacted>", redact_sensitive("password=hunter2", {}))

        def test_11_structured_parse_and_ambiguous_rejection(self):
            proposal = parse_model_output('{"explanation":"ok","language":"bash","code":"echo hi"}')
            self.assertEqual(proposal.code, "echo hi")
            self.assertIsNone(parse_model_output("run echo hi"))

        def test_12_offline_cache_detection(self):
            snapshots = self.config.model_cache / f"models--{MODEL.replace('/', '--')}" / "snapshots" / "abc"
            snapshots.mkdir(parents=True)
            (snapshots / "config.json").write_text("{}")
            (snapshots / "model.safetensors").write_bytes(b"weights")
            self.assertTrue(ModelEngine(self.config).cache_present())

        def test_12b_model_output_is_not_shown(self):
            raw = '{"explanation":"internal","language":"bash","code":"true"}'

            class Streamer:
                def __init__(self, *args, **kwargs): pass
                def __iter__(self): return iter([raw])
                def end(self): pass

            tokenizer = Mock()
            tokenizer.apply_chat_template.return_value = {}
            tokenizer.encode.return_value = [1]
            model = Mock(device="cpu")
            engine = ModelEngine(self.config)
            engine.load = Mock(return_value=(tokenizer, model))
            fake_torch = types.SimpleNamespace(inference_mode=Mock(return_value=contextlib.nullcontext()))
            fake_transformers = types.SimpleNamespace(TextIteratorStreamer=Streamer)
            with patch.dict(sys.modules, {"torch": fake_torch, "transformers": fake_transformers}), \
                 patch("sys.stdout.isatty", return_value=True), patch("builtins.print") as output:
                self.assertEqual(engine.generate([]), raw)
            self.assertNotIn(raw, "".join(str(call) for call in output.call_args_list))

        def test_12c_stderr_is_shown_only_on_failure(self):
            result = subprocess.CompletedProcess([], 0, "", "minor warning\n")
            with patch("builtins.print") as output:
                show_result(result, True, "exit-code")
            self.assertNotIn("minor warning", "".join(str(call) for call in output.call_args_list))

            with patch("builtins.print") as output:
                show_result(result, False, "exit-code:1")
            self.assertIn("minor warning", "".join(str(call) for call in output.call_args_list))

        def test_13_corrupt_database_is_preserved(self):
            self.db.close(); (self.config.cache_dir / "system.sqlite").write_bytes(b"not sqlite")
            recovered = SystemDatabase(self.config.cache_dir / "system.sqlite")
            self.assertIsNotNone(recovered.recovered_path)
            self.assertTrue(recovered.recovered_path.exists())
            recovered.close()
            self.db = SystemDatabase(self.config.cache_dir / "system.sqlite")

        def test_14_semantic_file_validation(self):
            target = self.root / "created"; target.touch()
            proposal = CodeProposal("touch", "bash", shlex.join(["touch", str(target)]))
            ok, method = Validator().validate(proposal, subprocess.CompletedProcess([], 0, "", ""))
            self.assertTrue(ok); self.assertTrue(method.startswith("path-exists"))

        def test_15_generalization_needs_two_successful_variants(self):
            store = SkillStore(self.db)
            first = CodeProposal("copy", "bash", "cp /a /b", generated_code="cp /a /b")
            skill_id, version = store.create_candidate("copy /a /b", first, first.code)
            store.record_outcome(skill_id, version, True)
            skills, _ = store.retrieve("copy /c /d")
            self.assertIsNone(store.proposal_from_skill("copy /c /d", skills[0]))
            second = CodeProposal("copy", "bash", "cp /c /d", generated_code="cp /c /d")
            _, version = store.create_candidate("copy /c /d", second, second.code)
            store.record_outcome(skill_id, version, True)
            skills, _ = store.retrieve("copy /e /f")
            reused = store.proposal_from_skill("copy /e /f", skills[0])
            self.assertEqual(reused.code, "cp /e /f")

        def test_16_cached_model_load_is_forced_offline(self):
            snapshots = self.config.model_cache / f"models--{MODEL.replace('/', '--')}" / "snapshots" / "abc"
            snapshots.mkdir(parents=True, exist_ok=True)
            (snapshots / "config.json").write_text("{}")
            (snapshots / "model.safetensors").write_bytes(b"weights")
            tokenizer_loader, model_loader = Mock(), Mock()
            tokenizer_loader.from_pretrained.return_value = Mock()
            loaded_model = Mock(); model_loader.from_pretrained.return_value = loaded_model
            fake_torch = types.SimpleNamespace(
                cuda=types.SimpleNamespace(is_available=lambda: False),
                float16="float16", bfloat16="bfloat16")
            fake_transformers = types.SimpleNamespace(
                AutoTokenizer=tokenizer_loader, AutoModelForCausalLM=model_loader)
            with patch.dict(sys.modules, {"torch": fake_torch, "transformers": fake_transformers}):
                ModelEngine(self.config).load()
            self.assertTrue(tokenizer_loader.from_pretrained.call_args.kwargs["local_files_only"])
            self.assertTrue(model_loader.from_pretrained.call_args.kwargs["local_files_only"])
            loaded_model.eval.assert_called_once_with()

        def test_17_version_one_schema_is_migrated(self):
            path = self.root / "old.sqlite"
            connection = sqlite3.connect(path)
            connection.executescript("""CREATE TABLE schema_info(version INTEGER NOT NULL);
              INSERT INTO schema_info VALUES(1);
              CREATE TABLE skill_versions(
                id INTEGER PRIMARY KEY, skill_id INTEGER NOT NULL, version INTEGER NOT NULL,
                request TEXT NOT NULL, normalized_intent TEXT NOT NULL, generated_code TEXT NOT NULL,
                approved_code TEXT NOT NULL, diff_summary TEXT NOT NULL, language TEXT NOT NULL,
                template_json TEXT, verification TEXT NOT NULL, model TEXT NOT NULL,
                status TEXT NOT NULL, created_at REAL NOT NULL, UNIQUE(skill_id,version));""")
            connection.close()
            migrated = SystemDatabase(path)
            columns = {row[1] for row in migrated.connection.execute("PRAGMA table_info(skill_versions)")}
            self.assertIn("template_status", columns)
            self.assertEqual(migrated.connection.execute("SELECT version FROM schema_info").fetchone()[0], SCHEMA_VERSION)
            migrated.close()

        def test_18_search_falls_back_without_fts5(self):
            self.db.upsert_application({"source":"native","identifier":"viewer","name":"Viewer",
                                        "description":"unicode image browser","launch":["viewer"]})
            self.db.connection.commit(); self.db.fts = False
            self.assertEqual(ApplicationResolver(self.db).search("unicode")[0]["identifier"], "viewer")

        def test_19_desktop_file_scan(self):
            desktop_dir = self.root / "desktop"; desktop_dir.mkdir()
            (desktop_dir / "paint.desktop").write_text(
                "[Desktop Entry]\nType=Application\nName=Paint App\nComment=Draw images\n"
                "Keywords=paint;draw;\nCategories=Graphics;\nExec=paint %F\n", encoding="utf-8")
            scanner = SystemScanner(self.config, self.db); scanner.DESKTOP_DIRS = (desktop_dir,)
            with patch("shutil.which", return_value=None):
                self.assertEqual(scanner.scan_desktop(), 1)
            row = self.db.connection.execute("SELECT * FROM applications WHERE source='desktop'").fetchone()
            self.assertEqual(json.loads(row["launch_json"]), ["paint"])
            self.assertIn("Draw images", row["description"])

        def test_20_editing_reused_skill_creates_a_new_version(self):
            store = SkillStore(self.db)
            original = CodeProposal("say", "bash", "echo old", generated_code="echo old")
            skill_id, version = store.create_candidate("say it", original, original.code)
            store.record_outcome(skill_id, version, True)
            reused = store.proposal_from_skill("say it", store.retrieve("say it")[0][0])
            agent = ZaAgent(self.config, database=self.db, engine=Mock())
            agent.executor.start = Mock(return_value=Mock(pid=1234))
            _, execution_id, new_skill_id, new_version = agent.execute_approved(
                "say it", reused, "echo changed")
            agent.record_feedback(execution_id, new_skill_id, new_version, True)
            versions = self.db.connection.execute(
                "SELECT generated_code,approved_code FROM skill_versions WHERE skill_id=? ORDER BY version",
                (skill_id,)).fetchall()
            self.assertEqual(len(versions), 2)
            self.assertEqual((versions[-1]["generated_code"], versions[-1]["approved_code"]),
                             ("echo old", "echo changed"))
            execution = self.db.connection.execute(
                "SELECT semantic_ok,result FROM executions WHERE id=?", (execution_id,)).fetchone()
            feedback = self.db.connection.execute(
                "SELECT kind,value FROM feedback WHERE execution_id=?", (execution_id,)).fetchone()
            self.assertEqual((execution["semantic_ok"], execution["result"]),
                             (1, "user-feedback:success"))
            self.assertEqual((feedback["kind"], feedback["value"]),
                             ("execution-result", "success"))

        def test_21_logo_uses_uppercase_pagga_font_and_rainbow(self):
            with patch("sys.stdout.isatty", return_value=False):
                plain = logo_lines()
            with patch("sys.stdout.isatty", return_value=True):
                colored = logo_lines()
            self.assertEqual(plain, list(LOGO_TEXT))
            self.assertEqual(len(plain), 4)
            self.assertEqual(plain[0], "")
            self.assertTrue(all(line.startswith(" ") for line in plain[1:]))
            self.assertEqual(plain[-1], " ▀▀▀ ▀ ▀")
            self.assertTrue(any(color in "".join(colored) for color in ANSI_RAINBOW))
            self.assertNotEqual(colored, plain)

        def test_22_partial_model_cache_is_resumed_online(self):
            snapshot = (self.config.model_cache
                        / f"models--{MODEL.replace('/', '--')}" / "snapshots" / "partial")
            snapshot.mkdir(parents=True)
            (snapshot / "config.json").write_text("{}")
            self.assertFalse(ModelEngine(self.config).cache_present())

        def test_23_link_apps_creates_symlinks_without_overwriting(self):
            app = self.root / "Editor.AppImage"
            app.write_text("#!/bin/sh\n", encoding="utf-8"); app.chmod(0o755)
            self.db.upsert_application({"source": "appimage", "identifier": str(app),
                                        "name": "Editor", "launch": [str(app)]})
            self.db.upsert_application({"source": "flatpak", "identifier": "org.gimp.GIMP",
                                        "name": "GIMP", "launch": ["flatpak", "run", "org.gimp.GIMP"]})
            self.db.upsert_application({"source": "desktop", "identifier": "keep",
                                        "name": "Keep", "launch": ["gtk-launch", "keep"]})
            self.db.upsert_application({"source": "desktop", "identifier": "system-tool",
                                        "name": "System Tool", "launch": ["gtk-launch", "system-tool"]})
            self.db.connection.commit()
            bin_dir = self.root / "bin"; bin_dir.mkdir()
            existing = bin_dir / "keep"; existing.write_text("mine", encoding="utf-8")
            system_bin = self.root / "system-bin"; system_bin.mkdir()
            system_tool = system_bin / "system-tool"
            system_tool.write_text("#!/bin/sh\n", encoding="utf-8"); system_tool.chmod(0o755)
            with patch.dict(os.environ, {"PATH": str(system_bin)}):
                result = link_applications(self.db, bin_dir, self.root / "launchers")
            self.assertEqual((result["created"], result["skipped"]), (2, 2))
            self.assertEqual((bin_dir / "editor").resolve(), app)
            self.assertTrue((bin_dir / "gimp").is_symlink())
            self.assertIn("flatpak run org.gimp.GIMP", (bin_dir / "gimp").resolve().read_text())
            self.assertEqual(existing.read_text(encoding="utf-8"), "mine")
            self.assertFalse((bin_dir / "system-tool").exists())

        def test_24_script_starts_in_background(self):
            started = time.monotonic()
            process = Executor().start(CodeProposal("wait", "bash", "sleep 1"), cwd=self.root)
            self.assertLess(time.monotonic() - started, 0.5)
            self.assertIsNone(process.poll())
            os.killpg(process.pid, signal.SIGTERM)
            process.wait(timeout=2)

        def test_25_background_output_is_captured(self):
            process = Mock()
            with patch("subprocess.Popen", return_value=process) as popen, \
                 patch("threading.Thread"):
                Executor().start(CodeProposal("launch", "bash", "app"), cwd=self.root)
            self.assertEqual(popen.call_args.kwargs.get("stdout"), subprocess.PIPE)
            self.assertEqual(popen.call_args.kwargs.get("stderr"), subprocess.PIPE)

        def test_25b_background_output_can_be_read(self):
            process = Executor().start(CodeProposal(
                "output", "bash", "printf stdout-text; printf stderr-text >&2"), cwd=self.root)
            process.wait(timeout=2)
            self.assertEqual(process_output(process, "stdout"), "stdout-text")
            self.assertEqual(process_output(process, "stderr"), "stderr-text")

        def test_26_interactive_records_immediate_feedback(self):
            agent = Mock()
            agent.scanner.scan.return_value = {"cached": True, "seconds": 0}
            agent.propose.return_value = (CodeProposal("proposal", "bash", "sleep 10"), {})
            process = Mock(pid=1234)
            process._za_stdout = "standard output"
            process._za_stderr = "standard error"
            process.poll.return_value = None
            agent.execute_approved.return_value = (process, 7, 8, 9)
            output = Mock(isatty=Mock(return_value=False))
            with patch("builtins.input", side_effect=["do it", "", "quit"]), \
                 patch("sys.stdout", new=output), \
                 patch(__name__ + ".output_feedback", return_value=True) as feedback:
                interactive(agent)
            feedback.assert_called_once_with(process)
            agent.record_feedback.assert_called_once_with(7, 8, 9, True, None)

        def test_27_stderr_panel_is_red_in_a_terminal(self):
            process = Mock(_za_stdout="", _za_stderr="failure")
            with patch("sys.stdout.isatty", return_value=True), patch("builtins.print") as output:
                show_output_panels(process, False, True)
            rendered = "\n".join(str(call.args[0]) if call.args else ""
                                 for call in output.call_args_list)
            self.assertIn(ANSI_RED, rendered)
            self.assertIn("Errori", rendered)
            self.assertIn(f"{ANSI_RED}failure", rendered)

        def test_28_click_selects_the_output_tab(self):
            tabs = output_tab_ranges()
            self.assertEqual(clicked_output_tab(tabs[0][1], 0, tabs), "stdout")
            self.assertEqual(clicked_output_tab(tabs[1][2] - 1, 0, tabs), "stderr")
            self.assertIsNone(clicked_output_tab(tabs[1][2], 0, tabs))
            self.assertIsNone(clicked_output_tab(tabs[0][1], 1, tabs))

        def test_29_output_lines_strip_terminal_codes_and_wrap(self):
            self.assertEqual(format_output_lines("\x1b[31mabcdefgh\x1b[0m", 4),
                             ["abcd", "efgh"])

        def test_30_output_status_is_explicit(self):
            running = Mock(pid=42); running.poll.return_value = None
            stopped = Mock(pid=42); stopped.poll.return_value = 0
            self.assertEqual(process_status(running)[0], "In esecuzione · PID 42")
            self.assertEqual(process_status(stopped)[0], "Terminato · codice 0")

        def test_31_plain_output_uses_clear_labels(self):
            process = Mock(_za_stdout="done", _za_stderr="")
            process.poll.return_value = 0
            with patch("sys.stdout.isatty", return_value=False), patch("builtins.print") as output:
                show_output_panels(process, True, True)
            rendered = "\n".join(str(call.args[0]) if call.args else ""
                                 for call in output.call_args_list)
            self.assertIn("Risultato esecuzione", rendered)
            self.assertIn("Output", rendered)
            self.assertIn("Errori", rendered)
            self.assertIn("nessun errore", rendered)

    suite = unittest.defaultTestLoader.loadTestsFromTestCase(Tests)
    return 0 if unittest.TextTestRunner(verbosity=2).run(suite).wasSuccessful() else 1


def build_parser():
    parser = argparse.ArgumentParser(description="Za (Zepto-Agent) — micro-agente Linux locale")
    parser.add_argument("--cache-dir", help="directory base della cache Za (o ZA_CACHE_DIR)")
    parser.add_argument("--verbose", action="store_true", help="mostra metriche diagnostiche")
    actions = parser.add_mutually_exclusive_group()
    actions.add_argument("--scan", action="store_true", help="aggiorna la mappa del sistema")
    actions.add_argument("--link-apps", action="store_true",
                         help="crea in ~/.local/bin i collegamenti alle applicazioni")
    actions.add_argument("--list-apps", action="store_true", help="elenca le applicazioni trovate")
    actions.add_argument("--find-app", metavar="QUERY", help="cerca un'applicazione")
    actions.add_argument("--list-skills", action="store_true", help="elenca le procedure apprese")
    actions.add_argument("--skill", metavar="NAME", help="mostra una procedura")
    actions.add_argument("--revoke-skill", metavar="NAME", help="revoca una procedura")
    actions.add_argument("--delete-skill", metavar="NAME", help="elimina una procedura revocata")
    actions.add_argument("--benchmark", action="store_true", help="mostra metriche leggere")
    actions.add_argument("--diagnose", action="store_true", help="controlla ambiente e cache")
    actions.add_argument("--rebuild-cache", action="store_true", help="ricostruisce solo dati rigenerabili")
    actions.add_argument("--self-test", action="store_true", help="esegue test non distruttivi")
    return parser


def command_line(agent, args):
    if args.scan:
        result = agent.scanner.scan(force=True); print(json.dumps(result, indent=2)); return
    if args.link_apps:
        scan = agent.scanner.scan(force=True)
        print(json.dumps({"scan": scan, **link_applications(agent.db)}, indent=2)); return
    if args.list_apps:
        for row in agent.db.connection.execute("SELECT name,source,path FROM applications ORDER BY name COLLATE NOCASE"):
            print(f"{row['name']}\t{row['source']}\t{row['path'] or ''}")
        return
    if args.find_app:
        for row in agent.resolver.search(args.find_app):
            print(f"{row['name']}\t{row['source']}\t{row['identifier']}")
        return
    if args.list_skills:
        for row in agent.skills.list():
            print(f"{row['name']}\t{row['status']}\t✓{row['successes']} ✕{row['failures']}")
        return
    if args.skill:
        row = agent.skills.get(args.skill); print(json.dumps(dict(row), indent=2, ensure_ascii=False) if row else "Skill non trovata."); return
    if args.revoke_skill:
        agent.skills.revoke(args.revoke_skill); print("Skill revocata."); return
    if args.delete_skill:
        row = agent.skills.get(args.delete_skill)
        if not row or row["status"] != "revoked":
            raise SystemExit("La skill deve esistere ed essere revocata prima dell'eliminazione.")
        agent.skills.revoke(args.delete_skill, delete=True); print("Skill eliminata."); return
    if args.rebuild_cache:
        agent.db.rebuild_regenerable(); print(json.dumps(agent.scanner.scan(force=True), indent=2)); return
    if args.diagnose:
        import torch
        print(json.dumps({"machine_cache": str(agent.config.cache_dir), "database": str(agent.db.path),
                          "database_recovered": str(agent.db.recovered_path or ""), "fts5": agent.db.fts,
                          "model": MODEL, "model_cached": agent.engine.cache_present(),
                          "cuda": torch.cuda.is_available(), "device":
                          torch.cuda.get_device_name(0) if torch.cuda.is_available() else "cpu",
                          "dtype": "float16" if torch.cuda.is_available() else "bfloat16",
                          "flatpak": bool(shutil.which("flatpak")), "gtk_launch": bool(shutil.which("gtk-launch"))},
                         indent=2)); return
    if args.benchmark:
        started = time.monotonic(); scan = agent.scanner.scan(); search = agent.skills.retrieve("benchmark")
        print(json.dumps({"scanner_seconds": scan["seconds"], "scanner_cached": scan["cached"],
                          "skill_search_seconds": search[1], "model_load_seconds": agent.engine.load_seconds,
                          **agent.engine.last_metrics}, indent=2)); return
    interactive(agent)


def main(argv=None):
    parser = build_parser(); args = parser.parse_args(argv)
    if args.self_test:
        return run_self_tests()
    config = Config.create(args.cache_dir, args.verbose)
    agent = ZaAgent(config)
    if agent.db.recovered_path:
        show_status("!", f"Database corrotto conservato in {agent.db.recovered_path}; indice rigenerato.", ANSI_YELLOW)
    command_line(agent, args)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
