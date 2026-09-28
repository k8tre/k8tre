#!/usr/bin/env python
# Extract and run fenced codeblocks from a markdown file

from argparse import ArgumentParser
from os import getenv
import re
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
parser.add_argument(
    "--tag",
    dest="tag",
    default=None,
    help="Filter codeblocks by tag / class (e.g. 'ci')",
)
parser.add_argument(
    "--languages",
    default="bash,shell,sh,",
    help="Comma-separated codeblock languages to extract (default: 'bash,shell,sh,')",
)

args = parser.parse_args()

allowed_languages = set(args.languages.split(","))

raw_blocks = []
inside_code = False
current_lang = ""
tags = []
script = []
block_start_line = 0
n = 0

with open(args.input) as f:
    for line in f:
        n += 1
        if line.startswith("```"):
            if not inside_code:
                inside_code = True
                info = line[3:].strip()
                current_lang = re.split(r"[\s{]", info)[0]
                tags = re.findall(r"\.([a-zA-Z0-9_-]+)", info)
                block_start_line = n
                script = []
            else:
                inside_code = False
                raw_blocks.append((current_lang, tags, "".join(script), block_start_line))
                script = []
        elif inside_code:
            for sub in args.sub:
                find, replace = sub.split("=", 1)
                line = line.replace(find, replace)
            script.append(line)

if inside_code:
    raise ValueError(f"Line {n}: Incomplete script: Missing closing ```")

if args.tag is not None:
    selected_blocks = [
        (i, block) for i, block in enumerate(raw_blocks)
        if args.tag in block[1]
    ]
else:
    selected_blocks = list(enumerate(raw_blocks))

for idx, (lang, tags, s, start_line) in selected_blocks:
    if lang not in allowed_languages:
        print(f"Skipping block {idx} (line {start_line}, language '{lang}')")
        continue

    if CI:
        firstline = s.strip().splitlines()[0] if s.strip() else ""
        print(f"::group::Block {idx}: {firstline}")

    tags_str = f" tags: {tags}" if tags else ""
    print(f"Running Block {idx} (line {start_line}, lang: '{lang}'{tags_str})\n```\n{s}\n```", flush=True)
    if args.run:
        run(["bash", "-o", "errexit", "-o", "xtrace", "-c", s], check=True)

    if CI:
        print("::endgroup::")
