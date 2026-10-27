"""Collections run as jobs: one worker thread, one job at a time, every run logged in the job table."""
from __future__ import annotations

import queue
import sys
import threading

from sqlalchemy import Engine
from sqlalchemy.orm import Session

from . import findings, sources
from .auth import _now
from .models import Job, SourceConfig, now, source

ACTIVE = ("queued", "running")


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
            self.run(self.q.get())

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
                job.summary = sources.collect(s, self.cfg, sc, log)
                log(job.summary)
                from .cli import load_specs
                out = findings.run(s, load_specs(self.cfg))
                log(f"Findings recomputed: {len(out)}")
                job.status = "ok"
            except Exception as e:  # one failed source must not stop the worker
                s.rollback()
                job.status, job.summary = "error", sources.explain(e, sc)
                log(f"Failed: {job.summary}")
                if sc is not None:
                    src = source(s, sc.name, sc.type)
                    src.status, src.error, src.last_run = "error", job.summary, now()
                    s.commit()
            job.finished = _now()
            js.commit()
            return job
