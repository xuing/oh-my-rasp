"""Which agent line a probe is testing.

probes/run.py tells every probe in the environment variable OHMYRASP_PROBE_TRACK: "8",
"11" or "17" for a backport line and "main" for the primary line, the same for the
line's own JAR and for the universal JAR. Without it (a probe run by hand), a JAR that
holds one line names it; a JAR that holds several lines cannot, and the probe stops.
LAUNCHER mirrors the launcher's range table for the launcher probe and the registry.
"""
from __future__ import annotations

import functools
import json
import os
from pathlib import Path
import re
import subprocess
import zipfile

PRIMARY = "main"
PRIMARY_HOOKS = "io/ohmyrasp/agent/hook/OhMyRaspHooks.class"
# (track, lowest Java, highest Java or None), in the order the launcher prefers them.
LAUNCHER = ((PRIMARY, 21, None), ("17", 17, None), ("11", 11, None), ("8", 8, 8))
ENVIRONMENT = "OHMYRASP_PROBE_TRACK"
LINE_NAMES = {PRIMARY: "primary", "17": "java17", "11": "java11", "8": "java8"}


def hooks_class(track: str) -> str:
    return PRIMARY_HOOKS if track == PRIMARY else f"io/ohmyrasp/agent/java{track}/Java{track}RaspHooks.class"


def tracks_in(agent: Path) -> set[str]:
    """The lines a JAR holds: '8', '11', '17' and 'main' for the primary line."""
    with zipfile.ZipFile(agent) as jar:
        names = set(jar.namelist())
    return {track for track, _, _ in LAUNCHER if hooks_class(track) in names}


@functools.lru_cache(maxsize=None)
def java_major(java: str = "java") -> int:
    text = subprocess.run([java, "-version"], capture_output=True, text=True, check=True).stderr
    version = re.search(r'version "([^"]+)"', text)[1]
    return int(version.split(".")[1] if version.startswith("1.") else re.match(r"\d+", version)[0])


def launcher_choice(tracks: set[str], major: int) -> str | None:
    """The track the launcher starts on Java `major` from a JAR holding `tracks`, or None when none fits."""
    for track, low, high in LAUNCHER:
        if track in tracks and low <= major and (high is None or major <= high):
            return track
    return None


def track(agent: Path) -> str | None:
    """'8', '11' or '17' for a backport line and None for the primary line, as the probes have always
    told them apart."""
    named = os.environ.get(ENVIRONMENT)
    if named:
        if named not in LINE_NAMES:
            raise SystemExit(f"{ENVIRONMENT}={named}: expected one of {', '.join(LINE_NAMES)}")
        return None if named == PRIMARY else named
    held = tracks_in(agent)
    if len(held) != 1:
        raise SystemExit(f"{agent.name} holds the lines {sorted(held)}; set {ENVIRONMENT} to the one under test "
                         "(probes/run.py does)")
    chosen = next(iter(held))
    return None if chosen == PRIMARY else chosen


def start_track(line: str) -> str | None:
    """The track whose own start output this line is ("main", "8", "11" or "17"), or None. The primary prints
    "[OHMYRASP] agent started with ASM transformer"; a backport writes {"event":"ohmyrasp-java<N>-agent-start"}."""
    if line.startswith("[OHMYRASP] agent started with ASM transformer"):
        return PRIMARY
    if line.startswith('{"event":"ohmyrasp-java'):
        try:
            event = json.loads(line)["event"]
        except (ValueError, KeyError):
            return None
        for track in ("8", "11", "17"):
            if event == f"ohmyrasp-java{track}-agent-start":
                return track
    return None
