"""Collections run as jobs: one worker thread, one job at a time, every run logged in the job table."""
from __future__ import annotations

import queue
import sys
import threading
import time
from datetime import datetime, timedelta

from sqlalchemy import Engine
from sqlalchemy.orm import Session

from . import findings, sources
from .auth import _now
from .models import Job, SourceConfig, get_setting, now, source

ACTIVE = ("queued", "running")
GENERAL = {"collapse_threshold": 10, "min_hits": 5, "job_retention_days": 90}


def effective_cfg(s: Session, cfg: dict) -> dict:
    """config.toml overlaid with what was changed under Settings."""
    general = get_setting(s, "general")
    discovery = {**cfg.get("discovery", {}), **{k: general[k] for k in ("collapse_threshold", "min_hits") if k in general}}
    return {**cfg, "discovery": discovery}


def interrupted(engine: Engine) -> None:
    """At start-up: jobs left queued or running by a stopped process will never finish."""
    with Session(engine) as s:
        for j in s.query(Job).filter(Job.status.in_(ACTIVE)):
            j.status, j.summary, j.finished = "error", "Interrupted by a restart", _now()
        s.commit()


class Runner:
    def __init__(self, engine: Engine, cfg: dict, echo: bool = False):
        self.engine, self.cfg, self.echo = engine, cfg, echo
        self.q: queue.Queue[int] = queue.Queue()
        self.thread: threading.Thread | None = None
        self.lock = threading.Lock()

    def submit(self, s: Session, sc: SourceConfig, trigger: str = "manual") -> Job:
        """Queue a collection; a source already queued or running is not queued twice."""
        with self.lock:
            job = s.query(Job).filter(Job.source == sc.name, Job.status.in_(ACTIVE)).first()
            if job is None:
                job = Job(source=sc.name, trigger=trigger, created=_now())
                s.add(job)
                s.commit()
                self.q.put(job.id)
            if self.thread is None or not self.thread.is_alive():
                self.thread = threading.Thread(target=self._loop, name="waf-inv-jobs", daemon=True)
                self.thread.start()
            return job

    def submit_now(self, s: Session, sc: SourceConfig, trigger: str) -> Job:
        """Run in this thread (the CLI)."""
        job = Job(source=sc.name, trigger=trigger, created=_now())
        s.add(job)
        s.commit()
        return self.run(job.id)

    def _loop(self) -> None:
        while True:
            job_id = self.q.get()
            try:
                self.run(job_id)
            except Exception as e:  # the worker must outlive any one job; a restart marks that job interrupted
                print(f"jobs: job {job_id}: {type(e).__name__}: {e}", file=sys.stderr)

    def run(self, job_id: int) -> Job:
        with Session(self.engine, expire_on_commit=False) as js, Session(self.engine) as s:
            job = js.get(Job, job_id)
            sc = s.query(SourceConfig).filter_by(name=job.source).one_or_none()
            job.status, job.started = "running", _now()
            js.commit()

            def log(msg: str) -> None:
                job.log += f"{_now():%H:%M:%S} {msg}\n"
                js.commit()
                if self.echo:
                    print(f"[{job.source}] {msg}", file=sys.stderr)

            try:
                if sc is None:
                    raise ValueError("The source was deleted before the job ran")
                log(f"Collecting {sc.name}: {sources.TYPES[sc.type][0]}")
                cfg = effective_cfg(s, self.cfg)
                job.summary = sources.collect(s, cfg, sc, log)
                log(job.summary)
                from .cli import load_specs
                out = findings.run(s, load_specs(cfg))
                log(f"Findings recomputed: {len(out)}")
                job.status = "ok"
            except Exception as e:  # one failed source must not stop the worker
                s.rollback()
                sc = s.query(SourceConfig).filter_by(name=job.source).one_or_none()  # it may have been deleted meanwhile
                job.status, job.summary = "error", sources.explain(e, sc)
                log(f"Failed: {job.summary}")
                if sc is not None:
                    retry = job.trigger == "schedule" and sources.collection(s)["retry"]
                    src = source(s, sc.name, sc.type)
                    src.status, src.error, src.last_run = "error", job.summary, now()
                    if retry:
                        sc.settings = {**sc.settings, "retry_at": (_now() + sources.RETRY).isoformat()}
                    s.commit()
                    if retry:
                        log(f"Will try again at {_now() + sources.RETRY:%H:%M} UTC")
            job.finished = _now()
            js.commit()
            return job


MISSED = timedelta(minutes=5)  # a due time older than this was missed while the server was off


def tick(s: Session, runner: Runner, at: datetime) -> list[str]:
    """Queue every source whose scheduled time (or retry) has come; drop job history past its retention. Returns names queued."""
    queued, default = [], sources.collection(s)
    for sc in s.query(SourceConfig):
        if (retry := sc.settings.get("retry_at")) and datetime.fromisoformat(retry) <= at:
            sc.settings = {k: v for k, v in sc.settings.items() if k != "retry_at"}
            runner.submit(s, sc, trigger="retry")
            queued.append(sc.name)
        sched, nxt = sources.effective(sc.settings.get("schedule"), default), sc.settings.get("next_run")
        if not sched or sched.get("every", "off") == "off":
            continue
        if nxt and datetime.fromisoformat(nxt) <= at and (default["catch_up"] or datetime.fromisoformat(nxt) > at - MISSED):
            runner.submit(s, sc, trigger="schedule")
            queued.append(sc.name)
        if not nxt or datetime.fromisoformat(nxt) <= at:
            following = sources.next_run(sched, at)
            sc.settings = {**sc.settings, "next_run": following.isoformat() if following else None}
    days = get_setting(s, "general").get("job_retention_days", GENERAL["job_retention_days"])
    s.query(Job).filter(Job.finished < at - timedelta(days=days)).delete()
    s.commit()
    return queued


def start_scheduler(engine: Engine, runner: Runner, every: float = 30) -> threading.Thread:
    def loop() -> None:
        while True:
            try:
                with Session(engine) as s:
                    tick(s, runner, _now())
            except Exception as e:  # a bad row must not stop scheduling for good
                print(f"scheduler: {type(e).__name__}: {e}", file=sys.stderr)
            time.sleep(every)
    th = threading.Thread(target=loop, name="waf-inv-scheduler", daemon=True)
    th.start()
    return th
