#!/usr/bin/env python
# Extract and run fenced codeblocks from a markdown file

from argparse import ArgumentParser
from os import getenv
from subprocess import run

CI = getenv("CI") == "true"

parser = ArgumentParser(description="Extract fenced codeblocks from a markdown file")
parser.add_argument("input", help="Input markdown file")
parser.add_argument(
    "--sub",
    action="append",
    default=[],
    help="Substitute a string in the input file (string=replacement)",
)
parser.add_argument("--run", action="store_true", help="Run the code")

args = parser.parse_args()

scripts = []
inside_code = False
script = []
n = 0
with open(args.input) as f:
    for line in f:
        n += 1
        if line.startswith("```"):
            if line[3:].rstrip() not in ("", "bash"):
                raise ValueError(
                    f"Line {n}: Only bash code blocks are supported: {line}"
                )
            inside_code = not inside_code
            if not inside_code:
                scripts.append("".join(script))
                script = []
        elif inside_code:
            for sub in args.sub:
                find, replace = sub.split("=", 1)
                line = line.replace(find, replace)
            script.append(line)

if script:
    raise ValueError(f"Line {n}: Incomplete script: Missing closing ```")

for s in scripts:
    if CI:
        firstline = s.strip().splitlines()[0]
        print(f"::group::{firstline}")

    print(f"Running\n```\n{s}\n```", flush=True)
    if args.run:
        run(["bash", "-o", "errexit", "-o", "xtrace", "-c", s], check=True)

    if CI:
        print("::endgroup::")
