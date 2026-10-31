#!/usr/bin/env python3
"""run_cycle.py -- WBS 8.2: one full auto-hardening cycle, end to end, with a person approving the result.

Run from the ai-attack-mapper folder on the testbed machine (testbed + Ollama up, Claude API key set for the Mapper):

  python orchestrator/run_cycle.py start --base 1 --seed 42 --verify-seed 43 --dry-run   # print every command, run nothing
  python orchestrator/run_cycle.py start --base 1 --seed 42 --verify-seed 43             # steps 1-10, then stops
  python orchestrator/run_cycle.py status [--cycle NAME]
  python orchestrator/run_cycle.py resume --cycle NAME                  # continue from the first unfinished step
  python orchestrator/run_cycle.py resume --cycle NAME --only gate      # re-run one step
  python orchestrator/run_cycle.py approve --cycle NAME                 # only this activates a prompt version
  python orchestrator/run_cycle.py rollback --cycle NAME                # re-activate the base version
  python orchestrator/run_cycle.py snapshot --to cycle_test.db          # copy alerts.db with the SQLite backup API

The cycle (each step calls an existing script; nothing here changes detection, the judge or the frozen clause rules):
  attack            run_round.py on the base version (Garak + PyRIT + benign replay, one seed)
  grade             annotate_run.py for that round, inside the testbed container
  classify          Mapper on every attack in the round that succeeded or was flagged (config: commands.classify)
  import            Mapper results into alerts.db by alert_id, backup first, inside the container (config: commands.import)
  playbooks         playbook generator (config: commands.playbooks; skipped while null)
  gate              gate.py --version <base> --run-like %_<round> [--require-mapper --mapper-run <run>]
  harden            harden.py --eligible ... --skip-families <config> --apply   (stores the new version, NOT active)
  verify_candidate  run_round.py on the new version, verify seed      } identical flags (seed, probes, PyRIT, benign limit)
  grade_candidate   annotate_run.py                                    } for both rounds; together about 4-5 hours
  verify_base       run_round.py on the base version, same verify seed }
  grade_base        annotate_run.py                                    }
  utility           utility_check.py --versions <base>,<new> --limit 1380
  decide            live_results.py (eligible prompts of every cycle count as seen) + decide.py --variants fresh
  evaluate          Shadi's 7.2 harness (config: commands.evaluate; skipped while null)
  summary           summary.md, then STOP: a person reads it and runs approve

Rules built in (Aneeq's review, Oct 31):
  * classify sends every attack that succeeded, not only the flagged ones (the gate keeps unflagged successes)
  * all DB writes (annotate, Mapper import, hardening_applied) run inside the testbed container
  * gate is limited to the base version and the step-1 round
  * --skip-families comes from config.json; --target-families comes from harden.py's own history entry
  * seeds are recorded in orchestrator/seeds_used.json and never reused by another cycle
  * an interrupted or failed round is marked INVALID in rounds.json and the step starts a new round on resume
  * approve refuses anything but ACCEPT; a REJECT can be overridden only with --override-reason (logged), an INCONCLUSIVE
    never; live_results.py never gets --allow-ungraded
Stdlib only."""
import argparse, datetime, difflib, getpass, json, os, pathlib, re, shutil, sqlite3, subprocess, sys, time, urllib.request

HERE = pathlib.Path(__file__).resolve().parent
CYCLES, SEEDS, CONFIG = HERE / "cycles", HERE / "seeds_used.json", HERE / "config.json"
LOCK = CYCLES / ".lock"
# Set by apply_layout() from config.json: ROOT = folder holding attack_generation/, auto_hardening/, alert_store/, testbed/
# (default: the folder above orchestrator/); COMPOSE = where `docker compose` runs (default ROOT); PY = Python for the
# host-side scripts (run_round.py starts Garak and PyRIT with this interpreter, so it must be the venv that has them).
ROOT = COMPOSE = HERE.parent
AG, AH, AS = ROOT / "attack_generation", ROOT / "auto_hardening", ROOT / "alert_store"
ROUNDS_JSON = AG / "reports" / "rounds.json"
PY = sys.executable


def apply_layout(cfg):
    global ROOT, COMPOSE, AG, AH, AS, ROUNDS_JSON, PY
    base = HERE.parent
    ROOT = (base / cfg["root"]).resolve() if cfg.get("root") else base          # absolute paths work too
    COMPOSE = (base / cfg["compose_dir"]).resolve() if cfg.get("compose_dir") else ROOT
    AG, AH, AS = ROOT / "attack_generation", ROOT / "auto_hardening", ROOT / "alert_store"
    ROUNDS_JSON = AG / "reports" / "rounds.json"
    PY = cfg.get("python") or sys.executable
    missing = [str(p) for p in (AG, AH, AS, ROOT / "testbed", COMPOSE / "docker-compose.yml") if not p.exists()]
    if missing:
        sys.exit("config.json root / compose_dir do not match this machine; missing: " + ", ".join(missing))


def rel(p):
    """Short path for messages (cycle files live next to this script, which may be outside ROOT)."""
    for base in (HERE.parent, ROOT):
        try:
            return str(pathlib.Path(p).resolve().relative_to(base))
        except ValueError:
            pass
    return str(p)

STEPS = [
    ("attack", "Attack round on the base version"),
    ("grade", "Grade the attack round (container)"),
    ("classify", "Mapper on every succeeded attack of the round, plus flagged alerts"),
    ("import", "Import Mapper results into the alert store (container)"),
    ("playbooks", "Playbooks for the classified alerts"),
    ("gate", "Gate: eligible attacks for hardening"),
    ("harden", "Store the hardened prompt as a new version (not active)"),
    ("verify_candidate", "Verification round on the new version"),
    ("grade_candidate", "Grade the new-version round (container)"),
    ("verify_base", "Verification round on the base version"),
    ("grade_base", "Grade the base-version round (container)"),
    ("utility", "Harmless-message check, base vs new"),
    ("decide", "Live results + decide.py verdict"),
    ("evaluate", "Before/after evaluation (7.2)"),
    ("summary", "Write summary.md and stop for approval"),
]
STEP_NAMES = [s for s, _ in STEPS]


class Stop(Exception):
    """End the run here without it being an error (nothing to harden, waiting for a team command, ...)."""


class StepFailed(Exception):
    pass


# ----------------------------------------------------------------------------------------------------------- helpers
def now():
    return datetime.datetime.now(datetime.timezone.utc).isoformat(timespec="seconds")


def load_json(path, default):
    try:
        return json.loads(pathlib.Path(path).read_text(encoding="utf-8"))
    except FileNotFoundError:
        return default


def save_json(path, data):
    path = pathlib.Path(path); path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(path.suffix + ".tmp")
    tmp.write_text(json.dumps(data, indent=2), encoding="utf-8")
    os.replace(tmp, path)


def load_config():
    if not CONFIG.exists():
        sys.exit(f"missing {CONFIG}")
    return json.loads(CONFIG.read_text(encoding="utf-8"))


def http(method, url, body=None, timeout=30):
    data = json.dumps(body).encode() if body is not None else None
    req = urllib.request.Request(url, data=data, method=method, headers={"Content-Type": "application/json"})
    with urllib.request.urlopen(req, timeout=timeout) as r:
        return json.loads(r.read().decode())


def sqlite_backup(src, dst):
    """Consistent copy with the SQLite backup API (safe while the testbed is writing; a file copy is not)."""
    dst = pathlib.Path(dst); dst.parent.mkdir(parents=True, exist_ok=True)
    s = sqlite3.connect("file:" + pathlib.Path(src).resolve().as_posix() + "?mode=ro", uri=True)
    d = sqlite3.connect(str(dst))
    with d:
        s.backup(d)
    d.close(); s.close()
    return dst


def ro(db):
    return sqlite3.connect("file:" + pathlib.Path(db).resolve().as_posix() + "?mode=ro", uri=True)


def invalid_rounds():
    return load_json(ROUNDS_JSON, {}).get("invalid", {})


def mark_round_invalid(token, reason):
    if not token or token.startswith("<") or token in invalid_rounds():
        return
    sys.path.insert(0, str(AG))
    import rounds  # attack_generation/rounds.py, same file run_round.py uses
    rounds.mark_invalid(token, reason)


# ------------------------------------------------------------------------------------------------------------- cycle
class Cycle:
    def __init__(self, name, cfg, dry=False):
        self.name, self.cfg, self.dry = name, cfg, dry
        self.dir = CYCLES / name
        self.state = load_json(self.dir / "state.json", None) if not dry else None

    # paths -------------------------------------------------------------------------------------------------------
    @property
    def db_name(self):
        return self.state["settings"]["db"]

    @property
    def db(self):
        return AS / self.db_name

    @property
    def db_c(self):
        return "/app/alert_store/" + self.db_name

    def f(self, name):
        return self.dir / name

    # state -------------------------------------------------------------------------------------------------------
    def save(self):
        if not self.dry:
            save_json(self.dir / "state.json", self.state)

    def step(self, name):
        return self.state["steps"].setdefault(name, {"status": "pending"})

    def val(self, key):
        v = self.state["values"].get(key)
        if v is None:
            if self.dry:
                return f"<{key}>"
            raise StepFailed(f"value '{key}' is not set yet (an earlier step has not finished)")
        return v

    def setv(self, key, value):
        self.state["values"][key] = value
        self.save()

    # running commands --------------------------------------------------------------------------------------------
    def run(self, step, cmd, cwd=None, on_line=None, ok_codes=(0,)):
        """Run one command, streaming its output to the console and to logs/<step>.log. Returns (rc, output)."""
        cmd = [str(c) for c in cmd]
        cwd = cwd or ROOT
        where = rel(cwd)
        print(f"\n$ [{where}] " + " ".join(c if " " not in c else f'"{c}"' for c in cmd), flush=True)
        if self.dry:
            return 0, ""
        log = self.dir / "logs" / f"{step}.log"; log.parent.mkdir(parents=True, exist_ok=True)
        env = dict(os.environ, PYTHONUNBUFFERED="1", PYTHONIOENCODING="utf-8")
        out = []
        with open(log, "a", encoding="utf-8") as lf:
            lf.write(f"\n===== {now()} $ {' '.join(cmd)}\n")
            proc = subprocess.Popen(cmd, cwd=cwd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, env=env,
                                    text=True, encoding="utf-8", errors="replace")
            try:
                for line in proc.stdout:
                    sys.stdout.write(line); lf.write(line); out.append(line)
                    if on_line:
                        on_line(line.rstrip("\n"))
                rc = proc.wait()
            except KeyboardInterrupt:
                proc.terminate()
                try:
                    proc.wait(timeout=20)
                except subprocess.TimeoutExpired:
                    proc.kill()
                lf.write("\n===== interrupted (Ctrl+C)\n")
                raise
            lf.write(f"===== exit {rc}\n")
        text = "".join(out)
        if rc not in ok_codes:
            raise StepFailed(f"exit code {rc}: {' '.join(cmd[:4])} ... (log: {rel(log)})")
        return rc, text

    def container(self, inner):
        """Command that runs `inner` inside a one-off testbed container (SQLite writes over the host mount fail)."""
        c = self.cfg
        mounts = [(AG, "/app/attack_generation"), (AH, "/app/auto_hardening"), (HERE, "/app/orchestrator"), (ROOT / "mapper", "/app/mapper")]
        cmd = list(c["container"])
        for host, target in mounts:
            cmd += ["-v", f"{host}:{target}:ro"]
        return cmd + [c["container_service"]] + list(inner)

    def team_command(self, key, extra, only=None):
        """Commands owned by a teammate, from config.json commands.<key>: a list of (cmd, cwd), or None while not available.
        "run" is one command (list of args) or several (list of lists, run in order, e.g. Gladwin's run + export-run)."""
        spec = self.cfg.get("commands", {}).get(key)
        if not spec:
            return None
        cdir_c = f"/app/orchestrator/cycles/{self.name}"
        values = {"python": PY, "root": str(ROOT), "cycle_dir": str(self.dir), "cycle_dir_c": cdir_c,
                  "db": str(self.db), "db_c": self.db_c, "base": self.state["settings"]["base"],
                  # one Mapper results file per cycle: the import refuses a source holding more than one run
                  "mapper_db": str(self.dir / "mapper_results.db"), "mapper_db_c": f"{cdir_c}/mapper_results.db"}
        values.update(extra)
        runs = spec["run"] if spec["run"] and isinstance(spec["run"][0], list) else [spec["run"]]
        if only is not None:          # format one command (a later one may use a value an earlier one printed)
            if only >= len(runs):
                return []
            runs = [runs[only]]
        out = []
        for run in runs:
            try:
                cmd = [str(p).format(**values) for p in run]
            except KeyError as e:
                raise StepFailed(f"config commands.{key} uses {{{e.args[0]}}}, which is not available for this step")
            out.append((self.container(cmd), COMPOSE) if spec.get("in_container") else (cmd, ROOT / spec.get("cwd", ".")))
        return out


# ------------------------------------------------------------------------------------------------------------- steps
def round_step(cy, step, version_key, seed_key):
    """One run_round.py round. A previous unfinished attempt of this step is marked INVALID (run_round.py cannot resume)."""
    st = cy.step(step)
    s = cy.state["settings"]
    prev = st.get("round")
    if prev and not cy.dry:
        if cy.state["values"].get(f"round_{step}") == prev:   # finished round, re-run on purpose (--only): keep it valid
            cy.state.setdefault("superseded_rounds", []).append({"step": step, "round": prev, "at": now()})
        else:                                                   # interrupted / failed attempt: never use its numbers
            mark_round_invalid(prev, f"orchestrator cycle {cy.name}: step '{step}' did not finish; superseded by a new round")
            if prev not in [r["round"] for r in cy.state.get("abandoned_rounds", [])]:
                cy.state.setdefault("abandoned_rounds", []).append({"step": step, "round": prev, "at": now()})
        st["round"] = None; cy.state["values"].pop(f"round_{step}", None); cy.save()
    version = s["base"] if version_key == "base" else cy.val(version_key)
    cmd = [PY, "run_round.py", "--prompt-version", version, "--seed", s[seed_key], "--probes", s["probes"]]
    if s["skip_pyrit"]:
        cmd.append("--skip-pyrit")
    if s["benign_limit"]:
        cmd += ["--benign-limit", s["benign_limit"]]

    def grab(line):
        m = re.match(r"^Round (\S+)$", line.strip())
        if m:
            st["round"] = m.group(1); cy.save()

    try:
        cy.run(step, cmd, cwd=AG, on_line=grab)
    except KeyboardInterrupt:
        mark_round_invalid(st.get("round"), f"orchestrator cycle {cy.name}: interrupted (Ctrl+C) during '{step}'")
        raise
    except StepFailed as e:
        tok = st.get("round")
        mark_round_invalid(tok, f"orchestrator cycle {cy.name}: run_round.py failed during '{step}' ({e})")
        raise StepFailed(f"round {tok or '(no token)'} failed and is marked INVALID; `resume` starts a new round. {e}")
    tok = st.get("round") or ("<round>" if cy.dry else None)
    if not tok:
        raise StepFailed("run_round.py finished but printed no round token")
    cy.setv(f"round_{step}", tok)


def grade_step(cy, step, round_step_name, judge_must_be_valid):
    tok = cy.val(f"round_{round_step_name}")
    inner = ["python3", "/app/attack_generation/annotate_run.py", tok, "--db", cy.db_c]
    rc, _ = cy.run(step, cy.container(inner), cwd=COMPOSE, ok_codes=(0, 3))
    if rc == 3:
        if judge_must_be_valid:
            mark_round_invalid(tok, f"orchestrator cycle {cy.name}: judge scores missing in round (annotate_run.py exit 3)")
            cy.step(round_step_name).update(status="failed", round=tok, error="judge scores missing; a new round is needed")
            cy.state["values"].pop(f"round_{round_step_name}", None)
            cy.state.setdefault("abandoned_rounds", []).append({"step": round_step_name, "round": tok, "at": now()}); cy.save()
            raise StepFailed(f"round {tok} has missing judge scores, so gate.py would skip it entirely. "
                             f"Fix the judge, then `resume` (a new attack round is started).")
        cy.state.setdefault("warnings", []).append(f"{tok}: judge scores incomplete; Garak grades still used (flags are not needed for the verdict)")
    if not cy.dry:
        con = ro(cy.db)
        n_null = con.execute("SELECT COUNT(*) FROM alerts WHERE run_id = ? AND attack_succeeded IS NULL", (f"garak_{tok}",)).fetchone()[0]
        n_all = con.execute("SELECT COUNT(*) FROM alerts WHERE run_id = ?", (f"garak_{tok}",)).fetchone()[0]
        con.close()
        print(f"garak_{tok}: {n_all} rows, {n_null} still ungraded")
        if n_all and n_null:
            cy.state.setdefault("warnings", []).append(f"garak_{tok}: {n_null} of {n_all} rows ungraded after annotate_run.py")


def step_attack(cy):
    round_step(cy, "attack", "base", "seed")


def step_grade(cy):
    grade_step(cy, "grade", "attack", judge_must_be_valid=True)


def step_classify(cy):
    tok = cy.val("round_attack")
    runs = [f"garak_{tok}", f"pyrit_{tok}", f"benign_{tok}"]
    ids_file = cy.f("classify_ids.txt")
    if not cy.dry:
        con = ro(cy.db)
        ids = [r[0] for r in con.execute(
            "SELECT id FROM alerts WHERE run_id IN (?, ?, ?) AND (attack_succeeded = 1 OR (category IS NOT NULL AND category != '')) ORDER BY id", runs)]
        n_succ = con.execute("SELECT COUNT(*) FROM alerts WHERE run_id IN (?, ?, ?) AND attack_succeeded = 1", runs).fetchone()[0]
        con.close()
        ids_file.write_text("\n".join(map(str, ids)) + ("\n" if ids else ""), encoding="utf-8")
        cy.setv("classify_count", len(ids)); cy.setv("succeeded_count", n_succ)
        print(f"{len(ids)} alerts to classify ({n_succ} attacks that succeeded, flagged or not; plus flagged ones) -> {ids_file.name}")
        if n_succ == 0:
            raise Stop("no attack succeeded in the attack round: nothing to harden")
    if not cy.state["settings"]["require_mapper"]:
        print("require_mapper is false in config.json: the Mapper is not needed for the gate")
    made = cy.cfg.get("commands", {}).get("classify") or None
    if made is None and cy.dry:
        print("(config.json commands.classify is not set: a real run stops here until it is)")
        return
    if made is None:
        if cy.state["settings"]["require_mapper"]:
            raise Stop("waiting for config.json commands.classify (Gladwin's live runner). Add it, then `resume`.")
        cy.step("classify")["note"] = "skipped: commands.classify not configured"
        return
    extra = {"ids_file": str(ids_file), "ids_file_c": f"/app/orchestrator/cycles/{cy.name}/classify_ids.txt", "round": tok}
    out, i = "", 0
    while True:   # one command at a time: e.g. `run` prints the Mapper run id, then `export-run --run-id {mapper_run}` uses it
        found = re.findall(cy.cfg["mapper_run_regex"], out)
        if found or cy.dry:
            extra["mapper_run"] = found[-1] if found else "<mapper_run>"
        step_cmds = cy.team_command("classify", extra, only=i)
        if not step_cmds:
            break
        cmd, cwd = step_cmds[0]
        out += cy.run("classify", cmd, cwd=cwd)[1]
        i += 1
    runs_found = re.findall(cy.cfg["mapper_run_regex"], out)
    run_id = runs_found[-1] if runs_found else ("<mapper_run>" if cy.dry else None)
    if not run_id:
        raise StepFailed(f"could not find the Mapper run id in the output (regex {cy.cfg['mapper_run_regex']!r})")
    cy.setv("mapper_run", run_id)


def step_import(cy):
    if not cy.state["values"].get("mapper_run") and not cy.dry:
        cy.step("import")["note"] = "skipped: no Mapper run"
        return
    run_id = cy.val("mapper_run")
    made = cy.team_command("import", {"mapper_run": run_id, "round": cy.val("round_attack")})
    if made is None and cy.dry:
        print("(config.json commands.import is not set: a real run stops here until it is)")
        return
    if made is None:
        raise Stop("waiting for config.json commands.import (Aneeq's import_mapper_results.py). Add it, then `resume`.")
    if not cy.dry and not cy.f("mapper_results.db").exists():
        raise StepFailed("no mapper_results.db in the cycle folder: commands.classify must write (or export) its run to {mapper_db}")
    for cmd, cwd in made:      # import_mapper_results.py checks the ids, backs up the alert store, then inserts
        cy.run("import", cmd, cwd=cwd)
    if cy.dry:
        return
    ids = [int(x) for x in cy.f("classify_ids.txt").read_text(encoding="utf-8").split()]
    con = ro(cy.db)
    good = {r[0] for r in con.execute("SELECT DISTINCT alert_id FROM mapper_results WHERE run_id = ? AND valid_json = 1", (run_id,))}
    con.close()
    failed = [i for i in ids if i not in good]
    cy.f("failed_calls.txt").write_text("\n".join(map(str, failed)) + ("\n" if failed else ""), encoding="utf-8")
    cy.setv("mapper_valid", len(good & set(ids))); cy.setv("mapper_failed", len(failed))
    print(f"Mapper run {run_id} in {cy.db_name}: {len(good & set(ids))} of {len(ids)} valid, {len(failed)} failed (failed_calls.txt, manual review)")
    if not good:
        raise StepFailed(f"no valid rows for {run_id} in {cy.db_name} after the import")


def step_playbooks(cy):
    made = cy.team_command("playbooks", {"mapper_run": cy.state["values"].get("mapper_run") or "", "round": cy.val("round_attack")})
    if made is None:
        cy.step("playbooks")["note"] = "skipped: commands.playbooks not configured yet"
        print("playbooks: not available yet (config.json commands.playbooks is null), skipped")
        return
    for cmd, cwd in made:
        cy.run("playbooks", cmd, cwd=cwd)


def step_gate(cy):
    s = cy.state["settings"]; tok = cy.val("round_attack")
    out = cy.f("eligible.jsonl")
    cmd = [PY, "gate.py", "--db", cy.db, "--version", s["base"], "--run-like", f"%_{tok}", "--rounds-json", ROUNDS_JSON, "--out", out]
    if s["require_mapper"]:
        cmd += ["--require-mapper", "--mapper-run", cy.val("mapper_run"), "--min-confidence", s["min_confidence"]]
    cy.run("gate", cmd, cwd=AH)
    if cy.dry:
        return
    rows = [json.loads(l) for l in out.read_text(encoding="utf-8").splitlines() if l.strip()]
    fams = {}
    for r in rows:
        k = r["family"].split(".")[0]; fams[k] = fams.get(k, 0) + 1
    cy.setv("eligible_count", len(rows)); cy.setv("eligible_families", fams)
    if not rows:
        raise Stop("the gate found no eligible attack: nothing to harden")


def step_harden(cy):
    s = cy.state["settings"]
    cmd = [PY, "harden.py", "--eligible", cy.f("eligible.jsonl"), "--base", s["base"], "--apply"]
    if s["skip_families"]:
        cmd += ["--skip-families", *s["skip_families"]]
    nothing = []
    try:
        _, out = cy.run("harden", cmd, cwd=AH, on_line=lambda l: nothing.append(l) if "no clause needed" in l else None)
    except StepFailed:
        if nothing:
            raise Stop("harden.py added no clause (every eligible family is skipped or below the minimum)")
        raise
    if cy.dry:
        return
    m = re.search(r"stored as version (\d+)", out)
    if not m:
        raise StepFailed("harden.py did not report a stored version")
    v = int(m.group(1))
    entry = None
    for line in (AH / "history.jsonl").read_text(encoding="utf-8").splitlines():
        if line.strip():
            j = json.loads(line)
            if j.get("new") == v and j.get("base") == s["base"]:
                entry = j
    if entry is None:
        raise StepFailed(f"no history.jsonl entry for version {v}")
    targets = [c for c in entry.get("clauses", []) if c != "default"]
    clash = sorted(set(targets) & set(s["skip_families"]))
    if clash:
        raise StepFailed(f"families both skipped and targeted: {clash}")
    cy.setv("candidate", v); cy.setv("clauses", entry.get("clauses", [])); cy.setv("target_families", targets)
    old = (ROOT / "testbed" / "prompts" / f"system_prompt_v{s['base']}.txt").read_text(encoding="utf-8").splitlines()
    new = (ROOT / "testbed" / "prompts" / f"system_prompt_v{v}.txt").read_text(encoding="utf-8").splitlines()
    cy.f("prompt_diff.txt").write_text("\n".join(difflib.unified_diff(old, new, f"v{s['base']}", f"v{v}", lineterm="")) + "\n", encoding="utf-8")
    print(f"candidate v{v} stored (not active); clauses {entry.get('clauses')}; target families {targets}; skipped {s['skip_families']}")


def step_verify_candidate(cy):
    round_step(cy, "verify_candidate", "candidate", "verify_seed")


def step_grade_candidate(cy):
    grade_step(cy, "grade_candidate", "verify_candidate", judge_must_be_valid=False)


def step_verify_base(cy):
    round_step(cy, "verify_base", "base", "verify_seed")


def step_grade_base(cy):
    grade_step(cy, "grade_base", "verify_base", judge_must_be_valid=False)


def step_utility(cy):
    s = cy.state["settings"]
    _, out = cy.run("utility", [PY, "utility_check.py", "--versions", f"{s['base']},{cy.val('candidate')}", "--limit", s["utility_limit"]], cwd=AH)
    if cy.dry:
        return
    m = re.search(r"review file:\s*(.+)", out)
    if not m:
        raise StepFailed("utility_check.py did not print a review file")
    src = pathlib.Path(m.group(1).strip())
    dst = cy.f(src.name); shutil.copy2(src, dst)
    cy.setv("utility_csv", dst.name)


def seen_files(cy):
    """Prompts that count as seen: the replay sets, plus the eligible prompts of EVERY cycle so far (the clauses were written
    from them). live_results.py only knows the replay sets, so without this the 'fresh' set overlaps the training attacks."""
    files = [ROOT / p for p in cy.cfg.get("seen_sets", [])] + [ROOT / p for p in cy.cfg.get("extra_seen", []) if not p.endswith(".jsonl")]
    texts = set()
    extra_jsonl = [ROOT / p for p in cy.cfg.get("extra_seen", []) if p.endswith(".jsonl")]   # gate.py --out files from manual runs
    for el in extra_jsonl + sorted(CYCLES.glob("*/eligible.jsonl")):
        for line in el.read_text(encoding="utf-8").splitlines():
            if line.strip():
                texts.add(json.loads(line)["prompt"].strip())
    out = cy.f("seen_eligible.json")
    if not cy.dry:
        save_json(out, [{"text": t} for t in sorted(texts)])
        cy.setv("seen_eligible_prompts", len(texts))
    return files + [out]


def step_decide(cy):
    s = cy.state["settings"]; base, cand = s["base"], cy.val("candidate")
    lr = cy.f("live_results.jsonl")
    cmd = [PY, "live_results.py", "--db", cy.db, "--runs", f"garak_{cy.val('round_verify_candidate')}", f"garak_{cy.val('round_verify_base')}",
           "--seen", *seen_files(cy), "--rounds-json", ROUNDS_JSON, "--out", lr]   # never --allow-ungraded
    _, out1 = cy.run("decide", cmd, cwd=AH)
    cmd = [PY, "decide.py", "--parent", base, "--candidate", cand, "--results", lr, "--variants", "fresh", "--utility", cy.f(cy.val("utility_csv"))]
    targets = cy.state["values"].get("target_families") if not cy.dry else ["<target_families>"]
    if targets:
        cmd += ["--target-families", ",".join(targets)]
    _, out2 = cy.run("decide", cmd, cwd=AH)
    if cy.dry:
        return
    cy.f("decide.txt").write_text(out1 + "\n" + out2, encoding="utf-8")
    m = re.search(r"VERDICT:\s*(\w+)", out2)
    if not m:
        raise StepFailed("decide.py printed no VERDICT")
    cy.setv("verdict", m.group(1))


def step_evaluate(cy):
    made = cy.team_command("evaluate", {"base_round": cy.val("round_verify_base"), "candidate_round": cy.val("round_verify_candidate"),
                                        "candidate": cy.val("candidate"), "mapper_run": cy.state["values"].get("mapper_run") or ""})
    if made is None:
        cy.step("evaluate")["note"] = "skipped: commands.evaluate not configured yet"
        print("evaluate: not available yet (config.json commands.evaluate is null), skipped")
        return
    for cmd, cwd in made:
        cy.run("evaluate", cmd, cwd=cwd)


def step_summary(cy):
    if cy.dry:
        print("\n(summary.md is written here, then the cycle stops for approval)")
        return
    write_summary(cy)
    print(f"\nSummary: {rel(cy.f('summary.md'))}")
    v = cy.state["values"]
    print(f"VERDICT {v.get('verdict')}. Nothing is active yet. Next: python orchestrator/run_cycle.py approve --cycle {cy.name}")


FUNCS = {n: globals()[f"step_{n}"] for n in STEP_NAMES}


def write_summary(cy):
    s, v = cy.state["settings"], cy.state["values"]
    L = [f"# Cycle {cy.name}", "",
         f"Started {cy.state['created']} by {cy.state['by']}. Base prompt v{s['base']}, "
         + (f"attack seed {s['seed']}" if s["seed"] is not None else f"existing attack round {v.get('round_attack')}")
         + f", verify seed {s['verify_seed']}.",
         f"Probes {s['probes']}; PyRIT {'off' if s['skip_pyrit'] else 'on'}; harmless messages per round {s['benign_limit'] or 'all'}; "
         f"utility check {s['utility_limit']} messages; database {s['db']}.", "",
         "## Result", "",
         f"- **Verdict: {v.get('verdict', 'not reached')}**" + (f" for candidate v{v['candidate']} vs v{s['base']}" if v.get("candidate") else ""),
         f"- Attack round `{v.get('round_attack', '-')}`: {v.get('succeeded_count', '-')} attacks succeeded; {v.get('classify_count', '-')} alerts sent to the Mapper",
         f"- Mapper run `{v.get('mapper_run', '-')}`: {v.get('mapper_valid', '-')} valid, {v.get('mapper_failed', '-')} failed (failed_calls.txt, manual review)",
         f"- Eligible for hardening: {v.get('eligible_count', '-')} {v.get('eligible_families', '')}",
         f"- Clauses added: {v.get('clauses', '-')}; skipped families: {s['skip_families']}; target families: {v.get('target_families', '-')}",
         f"- Verification rounds (seed {s['verify_seed']}): candidate `{v.get('round_verify_candidate', '-')}`, base `{v.get('round_verify_base', '-')}`",
         f"- Seen prompts excluded from the fresh set: replay sets + {v.get('seen_eligible_prompts', '-')} eligible prompts from all cycles",
         "", "## Steps", "", "| Step | Status | Note |", "|---|---|---|"]
    for n, label in STEPS:
        st = cy.state["steps"].get(n, {})
        L.append(f"| {label} | {st.get('status', 'pending')} | {st.get('error') or st.get('note') or ''} |")
    if cy.state.get("abandoned_rounds"):
        L += ["", "## Rounds marked INVALID by this cycle", ""] + [f"- `{a['round']}` ({a['step']}, {a['at']})" for a in cy.state["abandoned_rounds"]]
    if cy.state.get("warnings"):
        L += ["", "## Warnings", ""] + [f"- {w}" for w in cy.state["warnings"]]
    if cy.f("decide.txt").exists():
        L += ["", "## decide.py", "", "```", cy.f("decide.txt").read_text(encoding="utf-8").strip()[-3000:], "```"]
    if cy.f("prompt_diff.txt").exists():
        L += ["", "## Prompt change", "", "```diff", cy.f("prompt_diff.txt").read_text(encoding="utf-8").strip(), "```"]
    ap = load_json(cy.f("approval.json"), None)
    L += ["", "## Approval", ""] + ([f"- {e['action']} v{e['version']} by {e['by']} at {e['at']}" + (f" (override: {e['override_reason']})" if e.get("override_reason") else "")
                                     for e in ap["events"]] if ap else ["- Waiting: `python orchestrator/run_cycle.py approve --cycle " + cy.name + "`"])
    cy.f("summary.md").write_text("\n".join(L) + "\n", encoding="utf-8")


# --------------------------------------------------------------------------------------------------------- execution
def acquire_lock(dry):
    if dry:
        return
    CYCLES.mkdir(parents=True, exist_ok=True)
    try:
        fd = os.open(LOCK, os.O_CREAT | os.O_EXCL | os.O_WRONLY)
        os.write(fd, f"{os.getpid()} {now()}".encode()); os.close(fd)
    except FileExistsError:
        sys.exit(f"another cycle is running ({LOCK.read_text()}). If that is wrong (it crashed), delete {rel(LOCK)}.")


def release_lock(dry):
    if not dry:
        LOCK.unlink(missing_ok=True)


def execute(cy, only=None, stop_after=None):
    names = [only] if only else STEP_NAMES
    if only:   # anything after a re-run step was built on its old output
        for later in STEP_NAMES[STEP_NAMES.index(only) + 1:]:
            st = cy.state["steps"].get(later)
            if st and st.get("status") == "done":
                st.update(status="pending", note=f"stale: re-run after --only {only}")
        cy.save()
    acquire_lock(cy.dry)
    try:
        for n in names:
            st = cy.step(n)
            if st["status"] == "done" and not only:
                continue
            print(f"\n{'=' * 80}\n[{cy.name}] step {STEP_NAMES.index(n) + 1}/{len(STEPS)}: {n} -- {dict(STEPS)[n]}\n{'=' * 80}", flush=True)
            st.update(status="running", started=now(), error=None, note=st.get("note") if only else None); cy.save()
            try:
                FUNCS[n](cy)
            except Stop as e:
                st.update(status="stopped", note=str(e), finished=now()); cy.save()
                print(f"\nSTOPPED at {n}: {e}")
                if not cy.dry:
                    write_summary(cy)
                return 0
            except StepFailed as e:
                st.update(status="failed", error=str(e), finished=now()); cy.save()
                print(f"\nFAILED at {n}: {e}\nFix it, then: python orchestrator/run_cycle.py resume --cycle {cy.name}")
                if not cy.dry:
                    write_summary(cy)
                return 1
            except KeyboardInterrupt:
                st.update(status="interrupted", finished=now()); cy.save()
                print(f"\nINTERRUPTED at {n}. Continue with: python orchestrator/run_cycle.py resume --cycle {cy.name}")
                return 130
            st.update(status="done", finished=now()); cy.save()
            if n == stop_after:
                if not cy.dry:
                    write_summary(cy)
                print(f"\nstopped after '{n}' (--stop-after)")
                return 0
        return 0
    finally:
        release_lock(cy.dry)


def check_seeds(name, seed, verify_seed):
    if seed == verify_seed:
        sys.exit("--seed and --verify-seed must differ (the verification rounds need prompts the attack round did not use)")
    used = load_json(SEEDS, {})
    for sd in (seed, verify_seed):
        if sd is None:
            continue
        u = used.get(str(sd))
        if u and u["cycle"] != name:
            sys.exit(f"seed {sd} was already used by cycle {u['cycle']} ({u['role']}). Pick new seeds (used: {sorted(map(int, used))}).")


def next_free_seeds(n=2):
    used = {int(k) for k in load_json(SEEDS, {})}
    out, s = [], 42
    while len(out) < n:
        if s not in used:
            out.append(s)
        s += 1
    return out


def cmd_start(a, cfg):
    if a.attack_round:      # step 1 is an existing round: its seed is whatever that round used, nothing to reserve
        if a.seed is not None:
            sys.exit("--seed has no effect with --attack-round (the round already ran); leave it out")
        if a.verify_seed is None:
            a.verify_seed = next_free_seeds(1)[0]
            print(f"verify seed not given: using unused seed {a.verify_seed}")
    elif a.seed is None or a.verify_seed is None:
        free = [s for s in next_free_seeds(4) if s not in (a.seed, a.verify_seed)]
        a.seed = a.seed if a.seed is not None else free.pop(0)
        a.verify_seed = a.verify_seed if a.verify_seed is not None else free.pop(0)
        print(f"seed not given: using unused seeds, attack {a.seed}, verify {a.verify_seed}")
    name = a.name or f"{datetime.datetime.now().strftime('%Y%m%d-%H%M')}_v{a.base}_s{a.seed if a.seed is not None else 'reuse'}"
    check_seeds(name, a.seed, a.verify_seed)
    db = a.db or cfg["db"]
    if not (AS / db).exists():
        sys.exit(f"{rel(AS / db)} not found")
    if not a.dry_run:
        if (CYCLES / name).exists():
            sys.exit(f"cycle {name} already exists; use resume")
        try:
            pr = http("GET", cfg["testbed"] + "/prompts")
        except Exception as e:  # noqa: BLE001
            sys.exit(f"testbed not reachable at {cfg['testbed']} ({e}); start it first")
        if a.base not in [p["version"] for p in pr["versions"]]:
            sys.exit(f"prompt version {a.base} is not stored on the testbed (stored: {[p['version'] for p in pr['versions']]})")
        if a.attack_round and a.attack_round in invalid_rounds():
            sys.exit(f"round {a.attack_round} is marked INVALID in rounds.json; gate.py would skip it")
    settings = {"base": a.base, "seed": a.seed, "verify_seed": a.verify_seed, "db": db,
                "probes": a.probes or cfg["probes"], "skip_pyrit": cfg["skip_pyrit"] if a.skip_pyrit is None else a.skip_pyrit,
                "benign_limit": a.benign_limit if a.benign_limit is not None else cfg["benign_limit"],
                "utility_limit": cfg["utility_limit"], "skip_families": list(cfg["skip_families"]),
                "require_mapper": cfg["require_mapper"], "min_confidence": cfg["min_confidence"]}
    cy = Cycle(name, cfg, dry=a.dry_run)
    cy.state = {"name": name, "created": now(), "by": getpass.getuser(), "settings": settings, "values": {}, "steps": {}}
    if a.attack_round:
        cy.state["steps"]["attack"] = {"status": "done", "round": a.attack_round, "note": "existing round reused (--attack-round)"}
        cy.state["values"]["round_attack"] = a.attack_round
    print(f"cycle {name}: base v{a.base}, seeds {a.seed}/{a.verify_seed}, db {db}" + ("  [DRY RUN: nothing is run or written]" if a.dry_run else ""))
    print("note: the two verification rounds plus the utility check take about 4-5 hours")
    if not a.dry_run:
        cy.dir.mkdir(parents=True)
        cy.save()
        used = load_json(SEEDS, {})
        if a.seed is not None:
            used[str(a.seed)] = {"cycle": name, "role": "attack", "at": now()}
        used[str(a.verify_seed)] = {"cycle": name, "role": "verify", "at": now()}
        save_json(SEEDS, used)
    return execute(cy, stop_after=a.stop_after)


def open_cycle(name, cfg):
    cy = Cycle(name, cfg)
    if cy.state is None:
        sys.exit(f"no cycle {name} (have: {', '.join(sorted(p.name for p in CYCLES.glob('*') if p.is_dir())) or 'none'})")
    return cy


def cmd_resume(a, cfg):
    cy = open_cycle(a.cycle, cfg)
    if a.only and a.only not in STEP_NAMES:
        sys.exit(f"--only must be one of: {', '.join(STEP_NAMES)}")
    ap = load_json(cy.f("approval.json"), {"events": []})
    if ap["events"] and ap["events"][-1]["action"] == "activate":
        sys.exit("this cycle's version is active; roll it back first or start a new cycle")
    return execute(cy, only=a.only, stop_after=a.stop_after)


def cmd_status(a, cfg):
    names = [a.cycle] if a.cycle else sorted(p.name for p in CYCLES.glob("*") if p.is_dir())
    if not names:
        print("no cycles yet"); return 0
    for n in names:
        cy = open_cycle(n, cfg); v = cy.state["values"]
        print(f"\n{n}  (base v{cy.state['settings']['base']}, seeds {cy.state['settings']['seed']}/{cy.state['settings']['verify_seed']}, "
              f"candidate v{v.get('candidate', '-')}, verdict {v.get('verdict', '-')})")
        for s, label in STEPS:
            st = cy.state["steps"].get(s, {})
            extra = st.get("error") or st.get("note") or ""
            print(f"  {s:17s} {st.get('status', 'pending'):12s} {extra}")
        ap = load_json(cy.f("approval.json"), None)
        if ap:
            for e in ap["events"]:
                print(f"  {e['action']}: v{e['version']} by {e['by']} at {e['at']}")
    return 0


def set_hardening_flag(cy, ids, value, step):
    ids_file = cy.f(f"hardening_ids_{value}.txt")
    ids_file.write_text("\n".join(map(str, ids)) + "\n", encoding="utf-8")
    inner = ["python3", "/app/orchestrator/mark_hardened.py", "--db", cy.db_c, "--ids-file",
             f"/app/orchestrator/cycles/{cy.name}/{ids_file.name}", "--value", str(value)]
    cy.run(step, cy.container(inner), cwd=COMPOSE)


def activate(cfg, version):
    http("POST", cfg["testbed"] + "/prompts/activate", {"version": version})
    active = http("GET", cfg["testbed"] + "/prompts")["active"]
    if active != version:
        raise StepFailed(f"asked to activate v{version}, testbed reports v{active} active")


def cmd_approve(a, cfg):
    cy = open_cycle(a.cycle, cfg); v = cy.state["values"]; s = cy.state["settings"]
    if cy.state["steps"].get("decide", {}).get("status") != "done":
        sys.exit("decide has not finished for this cycle; nothing to approve")
    ap = load_json(cy.f("approval.json"), {"events": []})
    if ap["events"] and ap["events"][-1]["action"] == "activate":
        sys.exit(f"v{v['candidate']} is already active from this cycle (use rollback to undo)")
    verdict, cand = v["verdict"], v["candidate"]
    print(f"cycle {cy.name}: candidate v{cand} vs base v{s['base']}, VERDICT {verdict}")
    if verdict == "INCONCLUSIVE":   # evidence missing (failed requests, too few attacks): re-run the check, never override
        sys.exit("refused: the verdict is INCONCLUSIVE, which means a check could not be run or was too small. "
                 "It cannot be activated, not even with an override. Fix the cause and re-run (resume --cycle ... --only decide, "
                 "or new verification rounds).")
    if verdict != "ACCEPT":
        if not a.override_reason:
            sys.exit(f"refused: the verdict is {verdict}, only ACCEPT can be activated. "
                     "To activate a REJECT anyway, give --override-reason \"...\" (it is logged in approval.json and summary.md).")
        print(f"OVERRIDE: activating despite {verdict}. Reason: {a.override_reason}")
    print("\n--- prompt change ---")
    print(cy.f("prompt_diff.txt").read_text(encoding="utf-8") if cy.f("prompt_diff.txt").exists() else "(no diff file)")
    print(f"--- decide.txt: {rel(cy.f('decide.txt'))}  |  summary: {rel(cy.f('summary.md'))}\n")
    typed = input(f"Type the version number to activate it on the live chatbot ({cand}), anything else cancels: ").strip()
    if typed != str(cand):
        sys.exit("cancelled; nothing changed")
    ids = [json.loads(l)["rowid"] for l in cy.f("eligible.jsonl").read_text(encoding="utf-8").splitlines() if l.strip()]
    backup = sqlite_backup(cy.db, AS / "backups" / f"{pathlib.Path(cy.db_name).stem}.{cy.name}.before-approve.db")
    print(f"backup: {rel(backup)}")
    try:
        activate(cfg, cand)
    except Exception as e:  # noqa: BLE001
        sys.exit(f"activation failed, hardening_applied NOT set: {e}")
    print(f"v{cand} is now active")
    event = {"action": "activate", "version": cand, "previous": s["base"], "verdict": verdict, "override_reason": a.override_reason,
             "by": getpass.getuser(), "at": now(), "hardening_applied_rows": len(ids)}
    try:
        set_hardening_flag(cy, ids, 1, "approve")
    except StepFailed as e:
        event["hardening_applied_error"] = str(e)
        print(f"WARNING: v{cand} is active but hardening_applied was not set: {e}\n"
              f"  re-run: docker compose run ... python3 /app/orchestrator/mark_hardened.py (see logs/approve.log)")
    ap["events"].append(event); save_json(cy.f("approval.json"), ap)
    write_summary(cy)
    print(f"approval.json written; {len(ids)} eligible alerts marked hardening_applied = 1")
    return 0


def cmd_rollback(a, cfg):
    cy = open_cycle(a.cycle, cfg); s = cy.state["settings"]
    ap = load_json(cy.f("approval.json"), None)
    if not ap or ap["events"][-1]["action"] != "activate":
        sys.exit("this cycle has no active approval to roll back")
    last = ap["events"][-1]
    typed = input(f"Type {last['previous']} to re-activate v{last['previous']} (currently v{last['version']} from this cycle): ").strip()
    if typed != str(last["previous"]):
        sys.exit("cancelled; nothing changed")
    activate(cfg, last["previous"])
    ids = [json.loads(l)["rowid"] for l in cy.f("eligible.jsonl").read_text(encoding="utf-8").splitlines() if l.strip()]
    set_hardening_flag(cy, ids, 0, "rollback")
    ap["events"].append({"action": "rollback", "version": last["previous"], "from": last["version"], "reason": a.reason,
                         "by": getpass.getuser(), "at": now()})
    save_json(cy.f("approval.json"), ap); write_summary(cy)
    print(f"v{last['previous']} active again; hardening_applied reset on {len(ids)} alerts")
    return 0


def cmd_snapshot(a, cfg):
    src, dst = AS / (a.source or cfg["db"]), AS / a.to
    if dst.exists():
        sys.exit(f"{rel(dst)} exists; pick another name")
    sqlite_backup(src, dst)
    print(f"{rel(dst)} written with the SQLite backup API. Use it with: start --db {a.to} --attack-round <existing round> --stop-after gate")
    return 0


def main():
    for stream in (sys.stdout, sys.stderr):   # Windows console: never crash on a character the code page lacks
        try:
            stream.reconfigure(errors="replace")
        except AttributeError:
            pass
    cfg = load_config()
    apply_layout(cfg)
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = ap.add_subparsers(dest="cmd", required=True)
    p = sub.add_parser("start", help="start a new cycle")
    p.add_argument("--base", type=int, required=True, help="prompt version the cycle hardens")
    p.add_argument("--seed", type=int, help="attack-round seed (default: next unused)")
    p.add_argument("--verify-seed", type=int, help="seed for both verification rounds (default: next unused)")
    p.add_argument("--probes", help=f"Garak probes (default {cfg['probes']})")
    p.add_argument("--skip-pyrit", action="store_true", default=None)
    p.add_argument("--benign-limit", type=int, help="harmless messages per round (default: all); cannot be 0")
    p.add_argument("--db", help=f"database file in alert_store/ (default {cfg['db']})")
    p.add_argument("--attack-round", help="reuse an existing graded round as step 1 (for testing on a snapshot)")
    p.add_argument("--name", help="cycle folder name (default <date>-<time>_v<base>_s<seed>)")
    p.add_argument("--stop-after", choices=STEP_NAMES)
    p.add_argument("--dry-run", action="store_true", help="print every command, run and write nothing")
    p = sub.add_parser("resume", help="continue a cycle")
    p.add_argument("--cycle", required=True); p.add_argument("--only", help="re-run just this step")
    p.add_argument("--stop-after", choices=STEP_NAMES)
    p = sub.add_parser("status"); p.add_argument("--cycle")
    p = sub.add_parser("approve", help="activate the candidate (asks you to type the version)")
    p.add_argument("--cycle", required=True); p.add_argument("--override-reason", help="needed to activate a non-ACCEPT verdict; logged")
    p = sub.add_parser("rollback", help="re-activate the base version")
    p.add_argument("--cycle", required=True); p.add_argument("--reason", default="")
    p = sub.add_parser("snapshot", help="copy the alert store with the SQLite backup API")
    p.add_argument("--to", required=True); p.add_argument("--source")
    a = ap.parse_args()
    if getattr(a, "benign_limit", None) == 0:
        sys.exit("--benign-limit 0 is not allowed: the benign run is part of every round")
    return {"start": cmd_start, "resume": cmd_resume, "status": cmd_status, "approve": cmd_approve,
            "rollback": cmd_rollback, "snapshot": cmd_snapshot}[a.cmd](a, cfg)


if __name__ == "__main__":
    sys.exit(main())
