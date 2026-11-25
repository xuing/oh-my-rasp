"""Pinned servlet APIs for offline packaged-agent fixtures."""
import hashlib
from pathlib import Path
from urllib.request import urlopen

def _manifest():
    apis = {}
    for line in Path(__file__).with_name("servlet-apis.properties").read_text().splitlines():
        line = line.strip()
        if not line or line.startswith(("#", "!")):
            continue
        namespace, entry = line.split("=", 1)
        coordinate, digest = entry.split(",")
        group, name, version = coordinate.split(":")
        artifact = f"{group.replace('.', '/')}/{name}/{version}/{name}-{version}.jar"
        apis[namespace] = (artifact, digest)
    return apis


APIS = _manifest()


def api_jar(namespace, work, local_dir):
    artifact, sha = APIS[namespace]
    api = (local_dir or work) / Path(artifact).name
    if local_dir is None:
        with urlopen("https://repo.maven.apache.org/maven2/" + artifact, timeout=25) as response:
            api.write_bytes(response.read(512 * 1024))
    if hashlib.sha256(api.read_bytes()).hexdigest() != sha:
        raise SystemExit(f"wrong {namespace} API digest")
    return api.resolve()
