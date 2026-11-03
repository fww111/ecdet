"""Run upstream CodeChecker with narrowly scoped platform compatibility fixes."""

from __future__ import annotations

import os
import re
from pathlib import Path


def install_platform_fixes() -> None:
    if os.name != "nt":
        return
    from codechecker_analyzer.analyzers.clangsa.analyzer import ClangSA

    original = ClangSA.ctu_mapping.__func__

    def ctu_mapping(cls):
        tool, mapping = original(cls)
        if tool:
            return tool, mapping
        version = cls.get_binary_version()
        if not version:
            return None, None
        name = "clang-extdef-mapping" if version.major > 7 else "clang-func-mapping"
        directory = Path(cls.analyzer_binary()).parent
        for filename in (f"{name}.exe", f"{name}-{version.major}.exe"):
            candidate = directory / filename
            if candidate.is_file():
                return str(candidate), ("externalDefMap.txt" if version.major > 7
                                        else "externalFnMap.txt")
        return None, None

    ClangSA.ctu_mapping = classmethod(ctu_mapping)

    from codechecker_analyzer.analyzers.clangsa import ctu_manager

    original_ast_cmd = ctu_manager.generate_ast_cmd

    def generate_ast_cmd(action, config, triple_arch, source):
        cmd, _ = original_ast_cmd(action, config, triple_arch, source)
        # Upstream removes the first character of a POSIX absolute path; on
        # Windows this leaves a ':' inside the output path. Match its own
        # ast_dump_path() mapping, which already handles Windows drives.
        ast_path = Path(config.ctu_dir) / triple_arch / ctu_manager.ast_dump_path(
            os.path.realpath(source))
        cmd[-1] = str(ast_path)
        return cmd, str(ast_path.parent)

    ctu_manager.generate_ast_cmd = generate_ast_cmd

    from tu_collector import tu_collector
    from ecdet.l3_analysis.codechecker_paths import split_command, windows_dependencies

    original_headers = tu_collector.get_dependent_headers

    def dependent_headers(command, build_dir_path, collect_toolchain=True):
        if isinstance(command, str):
            command = split_command(command)
        return original_headers(command, build_dir_path, collect_toolchain)

    tu_collector.__gather_dependencies = windows_dependencies
    tu_collector.get_dependent_headers = dependent_headers

    from codechecker_analyzer.analyzers.gcc.analyzer import Gcc

    original_gcc_cmd = Gcc.construct_analyzer_cmd

    def gcc_cmd(self, result_handler):
        # The upstream command discards object output using POSIX /dev/null.
        # Native Windows GCC needs the Windows null device instead.
        return [("-o" + os.devnull) if arg == "-o/dev/null" else arg
                for arg in original_gcc_cmd(self, result_handler)]

    Gcc.construct_analyzer_cmd = gcc_cmd

    from codechecker_report_converter.report import get_or_create_file
    from codechecker_report_converter.report.parser.sarif import Parser
    from urllib.parse import urlparse
    from urllib.request import url2pathname

    original_sarif_file = Parser._get_file

    def sarif_file(self, physical_loc):
        artifact = physical_loc.get("artifactLocation") or {}
        uri = artifact.get("uri") or ""
        # GCC emits absolute drive paths together with uriBaseId. Prefixing
        # the base again produces C:/C:\... and silently loses its findings.
        if re.match(r"^[a-zA-Z]:[/\\]", uri):
            return get_or_create_file(uri, self._file_cache)
        parsed = urlparse(uri)
        if parsed.scheme == "file":
            local = ("//" + parsed.netloc if parsed.netloc else "") + parsed.path
            return get_or_create_file(url2pathname(local), self._file_cache)
        return original_sarif_file(self, physical_loc)

    Parser._get_file = sarif_file

    source_root = os.environ.get("ECODET_CODECHECKER_SOURCE_ROOT")
    source_alias = os.environ.get("ECODET_CODECHECKER_SOURCE_ALIAS")
    if source_root and source_alias:
        def rewrite(value, old, new):
            for before, after in ((old, new), (old.replace('\\', '/'),
                                               new.replace('\\', '/'))):
                value = re.sub(re.escape(before), lambda _: after, value,
                               flags=re.IGNORECASE)
            return value

        def short_ast_path(source):
            import hashlib

            # Both AST generation and the function index use this mapping.
            # Fixed-size names avoid repeating a long source path in storage.
            source = os.path.normcase(os.path.realpath(source))
            return os.path.join("ast", hashlib.sha256(source.encode("utf-8")).hexdigest() + ".ast")

        ctu_manager.ast_dump_path = short_ast_path

        original_mentioned_path = ClangSA.analyzer_mentioned_file_real_path

        def mentioned_path(self, value):
            return os.path.realpath(original_mentioned_path(self, value))

        ClangSA.analyzer_mentioned_file_real_path = mentioned_path

        original_mapping_cmd = ctu_manager.get_extdef_mapping_cmd
        original_mapping_paths = ctu_manager.func_map_list_src_to_ast

        def mapping_cmd(action, config, source, func_map_cmd):
            # LLVM's standalone Windows mapping tool consumes narrow argv.
            # A project junction supplies ASCII arguments without copying code.
            return [rewrite(arg, source_root, source_alias) for arg in
                    original_mapping_cmd(action, config, source, func_map_cmd)]

        def mapping_paths(lines, on_demand):
            return original_mapping_paths(
                [rewrite(line, source_alias, source_root) for line in lines],
                on_demand)

        ctu_manager.get_extdef_mapping_cmd = mapping_cmd
        ctu_manager.func_map_list_src_to_ast = mapping_paths

        from codechecker_analyzer.analyzers.cppcheck.analyzer import Cppcheck

        original_cppcheck_cmd = Cppcheck.construct_analyzer_cmd
        original_cppcheck_post = Cppcheck.post_analyze

        def cppcheck_cmd(self, result_handler):
            return [rewrite(arg, source_root, source_alias) for arg in
                    original_cppcheck_cmd(self, result_handler)]

        Cppcheck.construct_analyzer_cmd = cppcheck_cmd

        def cppcheck_post(self, result_handler):
            import plistlib

            original_cppcheck_post(self, result_handler)
            result = Path(result_handler.workspace) / result_handler.analyzer_result_file
            if result.is_file():
                with result.open("rb") as stream:
                    plist = plistlib.load(stream)
                if "files" in plist:
                    plist["files"] = [rewrite(path, source_alias, source_root)
                                      for path in plist["files"]]
                    with result.open("wb") as stream:
                        plistlib.dump(plist, stream)

        Cppcheck.post_analyze = cppcheck_post


def main() -> int | None:
    from codechecker_common.cli import main as upstream_main

    return upstream_main()


install_platform_fixes()  # Windows multiprocessing workers import this module too.


if __name__ == "__main__":
    raise SystemExit(main())
