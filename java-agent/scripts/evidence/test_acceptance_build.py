"""Guard: acceptance scripts build the agent through acceptance/lib/agent-build.sh."""
import importlib.util
from pathlib import Path
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


if __name__ == "__main__":
    unittest.main()
