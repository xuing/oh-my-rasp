"""Discover the acceptance scripts under java-agent/acceptance/.

Layout (see docs/development/vulhub-coverage.md):

  acceptance/runtime/<jdk>.sh                      JDK-level suites
  acceptance/vulhub/<component>/<scenario>-<jdk>.sh  one directory per Vulhub component
  acceptance/lib/                                  helpers sourced by the scripts

The Vulhub inventories (generated coverage doc, README metrics, evidence report) key on a
"target" name and a JDK token. Those names predate the directory layout, so `legacy_stem`
rebuilds the target from the component directory and the scenario part of the file name.
"""

import re
from pathlib import Path

ACCEPTANCE = Path(__file__).resolve().parent.parent / "acceptance"

# JDK tokens that end a Vulhub script name, longest first so "java7-legacy" wins over "legacy".
JDK_TOKENS = ("java6-legacy", "java7-legacy", "java8", "java11", "java17", "java21")

# Component directory -> the short prefix its targets have always used.
TARGET_PREFIX = {
    "apache-cxf": "cxf",
    "apache-druid": "druid",
    "h2database": "h2",
    "liferay-portal": "liferay",
    "xxl-job": "xxljob",
}


def runtime_and_vulhub_scripts(root: Path = ACCEPTANCE) -> list[Path]:
    """Every acceptance script that asserts detection events (runtime and Vulhub, not lib/)."""
    return sorted(
        [*root.glob("runtime/*.sh"), *root.glob("vulhub/*/*.sh")],
        key=lambda p: p.relative_to(root).as_posix(),
    )


def split_leaf(stem: str) -> tuple[str, str | None]:
    """'3088-java7-legacy' -> ('3088', 'java7-legacy'); 'java8' -> ('', 'java8'); 'setup-boundaries' -> (stem, None)."""
    for jdk in JDK_TOKENS:
        if stem == jdk:
            return "", jdk
        if stem.endswith("-" + jdk):
            return stem[: -len(jdk) - 1], jdk
    return stem, None


def legacy_stem(script: Path) -> str:
    """The target-plus-JDK name the flat file names used to carry, e.g. 'activemq-3088-java7-legacy'."""
    component = script.parent.name
    scenario, jdk = split_leaf(script.stem)
    if component == "java" or (component == "tomcat" and scenario.startswith("tomcat8")):
        # java/rmi-* and tomcat/tomcat8-* are real Vulhub sub-names; the scenario already names the target.
        target = scenario
    else:
        prefix = TARGET_PREFIX.get(component, component)
        target = f"{prefix}-{scenario}" if scenario else prefix
    return f"{target}-{jdk}" if jdk else target


# A script whose name says it only shows a boundary: an old JVM (Java 6 or 7) on which an agent line now
# skips and the JVM runs unprotected, or a setup or licence state that keeps a payload out of reach.
# Neither shows the agent blocking an exploit.
BOUNDARY = re.compile(r"legacy|boundar", re.I)


def is_boundary(script: Path, root: Path = ACCEPTANCE) -> bool:
    """True for a script that only shows a legacy-JVM or setup/licence boundary (by its name)."""
    return bool(BOUNDARY.search(script.relative_to(root).as_posix()))


def vulhub_scripts(root: Path = ACCEPTANCE) -> list[Path]:
    """Vulhub scenario scripts, ordered as the old flat file names sorted."""
    return sorted(root.glob("vulhub/*/*.sh"), key=lambda p: legacy_stem(p) + ".sh")
