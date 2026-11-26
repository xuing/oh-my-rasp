"""Guard: acceptance scripts build the agent through acceptance/lib/agent-build.sh."""
import importlib.util
import os
from pathlib import Path
import subprocess
import tempfile
import unittest

SCRIPTS = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location("check_acceptance_build", SCRIPTS / "check-acceptance-build.py")
guard = importlib.util.module_from_spec(spec)
spec.loader.exec_module(guard)

SOURCE = "# shellcheck source=acceptance/lib/agent-build.sh\nsource acceptance/lib/agent-build.sh\n"


class AcceptanceBuildGuardTest(unittest.TestCase):
    def test_every_acceptance_script_builds_through_the_helper(self):
        for path in guard.scripts():
            self.assertEqual(guard.violations(path.read_text()), [], str(path))

    def test_scan_finds_the_scripts(self):
        names = {p.name for p in guard.scripts()}
        self.assertIn("java8.sh", names)
        self.assertNotIn("agent-build.sh", names)
        self.assertGreater(len(names), 100)

    def test_a_path_from_one_machine_is_flagged(self):
        for line in ('vulhub_dir="${OHMYRASP_VULHUB_X_DIR:-/home/ubuntu/vulhub/tomcat/CVE-2017-12615}"\n',
                     'poc="${OHMYRASP_POC:-/tmp/vulhub-ohmyrasp-20260603/activemq/poc.py}"\n',
                     'src_dir=/Users/someone/vulhub/jetty/src\n'):
            self.assertEqual([n for n, _ in guard.violations(line)], [1], line)

    def test_the_vulhub_root_variable_and_container_paths_are_accepted(self):
        text = ('vulhub_dir="${OHMYRASP_VULHUB_X_DIR:-${OHMYRASP_VULHUB_ROOT:?set OHMYRASP_VULHUB_ROOT to a Vulhub checkout}/tomcat/x}"\n'
                'docker exec "$name" ls /home/weblogic/Oracle\n'
                + 'work="$(mktemp -d /tmp/ohmyrasp-shiro.XXXXXX)"\n')
        self.assertEqual(guard.violations(text), [])

    def test_one_line_docker_gradle_is_flagged(self):
        text = 'docker run --rm -v "$(pwd):/workspace" -w /workspace gradle:jdk25 gradle --no-daemon :agent-java8:agentJava8Jar\n'
        self.assertEqual([n for n, _ in guard.violations(text)], [1])

    def test_continued_docker_gradle_is_flagged_at_its_first_line(self):
        text = "set -e\ndocker run --rm -u 1000:1000 \\\n  -w /workspace \\\n  \"$image\" \\\n  gradle --no-daemon build\n"
        self.assertEqual([n for n, _ in guard.violations(text)], [2])

    def test_a_gradle_image_with_any_tag_is_flagged(self):
        for image in ("gradle:jdk25", "gradle:9.9.2-jdk25", "gradle:8.5.1-jdk21-alpine"):
            text = f'docker run --rm -v "$PWD:/work" {image} javac Hello.java\n'
            self.assertEqual(len(guard.violations(text)), 1, image)

    def test_the_helper_calls_are_accepted(self):
        text = SOURCE + (
            'host_agent_jar="$(ohmyrasp_agent_jar "$(pwd)/agent-java8/build/libs/ohmyrasp-agent-java8.jar")"\n'
            "ohmyrasp_build :agent-java8:agentJava8Jar >/dev/null\n"
            'docker run --rm "$(ohmyrasp_gradle_image)" javac --release 8 Hello.java\n'
        )
        self.assertEqual(guard.violations(text), [])

    def test_comments_may_mention_gradle(self):
        text = "# gradle:jdk25 used to be named here; docker run gradle --no-daemon\n"
        self.assertEqual(guard.violations(text), [])

    def test_using_the_helper_without_sourcing_it_is_flagged(self):
        problems = guard.violations("ohmyrasp_build :agent-java8:agentJava8Jar\n")
        self.assertEqual(len(problems), 1)
        self.assertIn("without sourcing", problems[0][1])

    def test_sourcing_by_agent_root_counts(self):
        text = 'source "${agent_root}/acceptance/lib/agent-build.sh"\nohmyrasp_build :agent-java8:agentJava8Jar\n'
        self.assertEqual(guard.violations(text), [])

    def test_a_host_gradle_build_is_flagged(self):
        for command in (
            "gradle --no-daemon :agent-java8:agentJava8Jar",
            "./gradlew build",
            "cd java-agent && ./gradlew build",
            "../gradlew -q tasks",
            "JAVA_HOME=/x gradle build",
            'jar="$(./gradlew -q jarPath)"',
            "true && gradle build",
        ):
            problems = guard.violations(command + "\n")
            self.assertEqual(len(problems), 1, command)
            self.assertIn("host", problems[0][1], command)

    def test_text_that_only_mentions_gradle_is_not_a_build(self):
        for command in (
            'echo "gradle is not used"',
            "echo 'run gradle build'",
            "ls gradle/ gradle.properties",
            "cat agent-java8/build.gradle.kts",
            'GRADLE_USER_HOME="$gradle_home"',
        ):
            self.assertEqual(guard.violations(command + "\n"), [], command)

    def test_a_path_qualified_gradle_in_docker_is_flagged(self):
        for command in (
            'docker run --rm -v "$PWD:/w" -w /w "$image" /opt/gradle/bin/gradle build',
            'docker run --rm -v "$PWD:/w" -w /w "$image" ./gradlew build',
            'docker run --rm "$image" sh -c "cd /w && /home/gradle/gradlew build"',
            'docker run --rm \\\n  "$image" \\\n  /usr/bin/gradle build',
        ):
            problems = guard.violations(command + "\n")
            self.assertEqual(len(problems), 1, command)
            self.assertIn("Docker", problems[0][1], command)
        # A mount or an environment variable named after Gradle is not the executable.
        text = 'docker run --rm -e GRADLE_USER_HOME=/gradle-home -v "$h:/gradle-home" "$image" javac X.java\n'
        self.assertEqual(guard.violations(text), [])

    def test_only_the_exact_helper_counts_as_sourced(self):
        build = "ohmyrasp_build :agent-java8:agentJava8Jar\n"
        for source in (
            "source acceptance/lib/agent-build.sh.bak",
            "source acceptance/lib/agent-build.sh.orig",
            "source other/acceptance/lib/agent-build.sh",
            "source acceptance/lib/old-agent-build.sh",
            "source acceptance/lib/agent-build.sh.bak # was agent-build.sh",
            "# source acceptance/lib/agent-build.sh",
        ):
            problems = guard.violations(source + "\n" + build)
            self.assertTrue(any("without sourcing" in why for _, why in problems), source)
        for source in (
            "source acceptance/lib/agent-build.sh",
            ". acceptance/lib/agent-build.sh",
            'source "${agent_root}/acceptance/lib/agent-build.sh"',
            "source acceptance/lib/agent-build.sh # the helper",
        ):
            self.assertEqual(guard.violations(source + "\n" + build), [], source)
        # Other libraries may be sourced.
        self.assertEqual(guard.violations(SOURCE + "source acceptance/lib/ysoserial.sh\n" + build), [])

    def test_a_comment_at_the_end_of_a_line_is_not_scanned(self):
        for text in (
            SOURCE + 'docker run --rm "$(ohmyrasp_gradle_image)" javac X.java # was gradle:9.9.2-jdk25\n',
            "echo ok  # docker run gradle:9.9.2 gradle build\n",
            "echo ok  # ./gradlew build\n",
            "# ohmyrasp_build is called below\necho nothing\n",
            "echo done # ohmyrasp_agent_jar\n",
        ):
            self.assertEqual(guard.violations(text), [], text)
        # A # inside a word or a quote is not a comment.
        self.assertEqual(len(guard.violations('docker run "$img" sh -c "echo a#b; gradle:9.9.2"\n')), 1)
        self.assertEqual(len(guard.violations("gradle build #not-a-comment-start\n")), 1)


HELPER_FILE = SCRIPTS.parent / "acceptance" / "lib" / "agent-build.sh"


class HelperTest(unittest.TestCase):
    """`ohmyrasp_build` with a fake `docker` that records its arguments."""

    def run_helper(self, gradle_home: str, cwd: str, caller: str = "ohmyrasp_build :x:y") -> tuple[str, list[str]]:
        with tempfile.TemporaryDirectory() as tmp:
            bin_dir = Path(tmp) / "bin"
            bin_dir.mkdir()
            calls = Path(tmp) / "docker-calls"
            fake = bin_dir / "docker"
            fake.write_text('#!/usr/bin/env bash\nprintf "%s\\n" "$*" >> "' + str(calls) + '"\n')
            fake.chmod(0o755)
            script = f'source "{HELPER_FILE}"\n{caller}\n'
            env = {
                **{k: v for k, v in os.environ.items() if not k.startswith("OHMYRASP_")},
                "PATH": f"{bin_dir}:{os.environ['PATH']}",
                "OHMYRASP_GRADLE_HOME": gradle_home,
            }
            done = subprocess.run(["bash", "-c", script], cwd=cwd, env=env, capture_output=True, text=True)
            output = done.stdout + done.stderr
            return output, (calls.read_text().splitlines() if calls.exists() else [])

    def test_a_relative_gradle_home_reaches_docker_as_an_absolute_path(self):
        with tempfile.TemporaryDirectory() as work:
            _, calls = self.run_helper("rel/gradle-home", work)
            self.assertEqual(len(calls), 1, calls)
            mount = [part for part in calls[0].split() if part.endswith(":/gradle-home")]
            self.assertEqual(mount, [str(Path(work).resolve() / "rel" / "gradle-home") + ":/gradle-home"])
            self.assertTrue((Path(work) / "rel" / "gradle-home").is_dir())

    def test_a_failing_step_in_an_if_condition_never_reaches_docker(self):
        # mkdir cannot create a directory below a regular file.
        with tempfile.TemporaryDirectory() as work:
            blocker = Path(work) / "file"
            blocker.write_text("x")
            output, calls = self.run_helper(
                str(blocker / "home"),
                work,
                caller="if ohmyrasp_build :x:y; then echo RAN; else echo FAILED; fi",
            )
            self.assertEqual(calls, [], output)
            self.assertIn("FAILED", output)
            self.assertNotIn("RAN", output)


if __name__ == "__main__":
    unittest.main()
