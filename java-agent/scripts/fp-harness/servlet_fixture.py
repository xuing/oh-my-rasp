"""Pinned servlet APIs for offline packaged-agent fixtures."""
import hashlib
from pathlib import Path
from urllib.request import urlopen

APIS = {
    "javax": ("javax/servlet/javax.servlet-api/3.1.0/javax.servlet-api-3.1.0.jar",
              "af456b2dd41c4e82cf54f3e743bc678973d9fe35bd4d3071fa05c7e5333b8482"),
    "jakarta": ("jakarta/servlet/jakarta.servlet-api/5.0.0/jakarta.servlet-api-5.0.0.jar",
                "33d3a5bda82c7d2f1b898685faa954f1fc34f7b0ae5c2f6ccc6d051e8a10973b"),
}


def api_jar(namespace, work, local_dir):
    artifact, sha = APIS[namespace]
    api = (local_dir or work) / Path(artifact).name
    if local_dir is None:
        with urlopen("https://repo.maven.apache.org/maven2/" + artifact, timeout=25) as response:
            api.write_bytes(response.read(512 * 1024))
    if hashlib.sha256(api.read_bytes()).hexdigest() != sha:
        raise SystemExit(f"wrong {namespace} API digest")
    return api.resolve()
