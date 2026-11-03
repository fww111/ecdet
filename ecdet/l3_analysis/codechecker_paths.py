"""Windows compiler dependency output handling for upstream TUCollector."""

from __future__ import annotations

import os
import re
import shlex
import subprocess


def parse_make_dependencies(text: str, directory: str) -> list[str]:
    text = re.sub(r"\\\r?\n", " ", text).removeprefix("__dummy:")
    tokens = re.findall(r"(?:\\[ \t#]|[^\s])+", text)
    return [os.path.realpath(os.path.join(directory,
                re.sub(r"\\([ \t#])", r"\1", token).replace("$$", "$")))
            for token in tokens]


def split_command(command: str) -> list[str]:
    # Native CodeChecker serializes argument arrays with POSIX single quotes;
    # existing Windows databases also contain raw double-quoted command lines.
    if "'" in command:
        return shlex.split(command, posix=True)
    return [arg.strip('"') for arg in shlex.split(command, posix=False)]


def windows_dependencies(command, directory: str) -> list[str]:
    args = split_command(command) if isinstance(command, str) else list(command)
    args = [arg.strip('"') for arg in args if arg]
    if not args:
        return []
    result = [args[0], "-E", "-M", "-MT", "__dummy"]
    takes_value = {"-o", "--output", "-MF", "-MT", "-MQ", "-MJ"}
    single = {"-MD", "-MMD", "-MM", "-MP", "-M", "-MG", "-MV"}
    index = 1
    while index < len(args):
        arg = args[index]
        if arg in takes_value:
            index += 2
            continue
        if arg in single or arg.startswith(("--output=", "-MF", "-MT", "-MQ", "-MJ")) \
                or (arg.startswith("-o") and len(arg) > 2):
            index += 1
            continue
        result.append(arg)
        index += 1
    output = subprocess.check_output(result, cwd=directory, encoding="utf-8", errors="replace")
    return parse_make_dependencies(output, directory)
