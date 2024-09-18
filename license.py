import sys
import json

# check the license before adding it here:
# we want to avoid viral licenses like GPL
ALLOWED = {
    "Unlicense",
    "MIT",
    "Apache-2.0",
    "BSL-1.0",
    "Unicode-DFS-2016",
    "BSD-3-Clause",
}

licenses = json.loads(sys.stdin.read())

for dep in licenses["dependencies"]:
    print(f"{dep["name"]}-{dep["version"]}: {", ".join(dep["licenses"])}")
    assert len(set(dep["licenses"]).intersection(ALLOWED)) > 0, dep
