"""Which agent line a probe is testing.

A per-line JAR holds one line. The universal JAR holds every line, and its launcher
(io.ohmyrasp.agent.launch.AgentLauncher) starts the one that fits the running Java, so
for that JAR the answer depends on the `java` the probe runs. LAUNCHER mirrors the
launcher's table; the launcher probe fails when the two disagree.
"""
from __future__ import annotations

import functools
from pathlib import Path
import re
import subprocess
import zipfile

PRIMARY = "main"
PRIMARY_HOOKS = "io/ohmyrasp/agent/hook/OhMyRaspHooks.class"
# (track, lowest Java, highest Java or None), in the order the launcher prefers them.
LAUNCHER = ((PRIMARY, 21, None), ("17", 17, None), ("11", 11, None), ("8", 8, 8))
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
    told them apart. A JAR with several lines answers for the line its launcher starts on `java`."""
    held = tracks_in(agent)
    chosen = next(iter(held)) if len(held) == 1 else launcher_choice(held, java_major())
    return None if chosen in (None, PRIMARY) else chosen
