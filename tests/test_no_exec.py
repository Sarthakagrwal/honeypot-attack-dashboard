"""Static safety scan — the honeypot must contain no execution primitives.

This is the enforced expression of the project's core safety principle: a
low-interaction honeypot SIMULATES services and must never have a path from
attacker-supplied bytes to code execution. The test fails the build if any
forbidden execution primitive appears in *code* anywhere in the ``honeypot/``
package, so the guarantee cannot silently regress.

The scan is done two ways for defence in depth:

* a token-level scan (via :mod:`tokenize`) that inspects only real code
  tokens — comments and string literals are deliberately ignored, because the
  package's docstrings legitimately *name* the forbidden primitives to explain
  what it refuses to do, and the fake shell stores canned output strings;
* an AST-level scan that catches imports and calls regardless of aliasing.
"""

from __future__ import annotations

import ast
import io
import tokenize
from pathlib import Path

# Package under audit: every .py file in honeypot/.
_PKG = Path(__file__).resolve().parents[1] / "honeypot"

# Dotted attribute accesses that could execute or evaluate attacker input.
# These are matched against the code's NAME/OP token stream only.
_FORBIDDEN_ATTRIBUTES = (
    "os.system",
    "os.popen",
    "os.execv",
    "os.execve",
    "os.execl",
    "os.execlp",
    "os.execvp",
    "os.spawnv",
    "os.spawnl",
    "pickle.load",
    "pickle.loads",
)

# Bare names that must never be *called* anywhere in the package.
_FORBIDDEN_CALL_NAMES = {"eval", "exec", "compile", "__import__"}

# Modules that must never be imported by the package.
_FORBIDDEN_MODULES = {"subprocess", "pty"}


def _python_files() -> list[Path]:
    """Return every .py file shipped in the honeypot package."""
    files = sorted(_PKG.rglob("*.py"))
    assert files, "no honeypot source files found — wrong path?"
    return files


def _code_token_string(path: Path) -> str:
    """Return a file's source with comments and string literals stripped.

    Only NAME / OP / NUMBER tokens survive, joined by spaces — enough to spot
    a real ``os.system`` call while ignoring any mention inside a docstring or
    a canned-output string constant.
    """
    text = path.read_text(encoding="utf-8")
    kept: list[str] = []
    try:
        for tok in tokenize.generate_tokens(io.StringIO(text).readline):
            if tok.type in (tokenize.NAME, tokenize.OP, tokenize.NUMBER):
                kept.append(tok.string)
    except tokenize.TokenError:  # pragma: no cover - source always tokenizes
        return text
    return " ".join(kept)


def test_no_forbidden_primitives_in_code() -> None:
    """No real code token may form a forbidden execution primitive."""
    offenders: list[str] = []
    for path in _python_files():
        code = _code_token_string(path)
        # Normalise away the spaces tokenize inserts around '.' so that
        # "os . system" matches the dotted form "os.system".
        normalised = code.replace(" . ", ".").replace(" .", ".").replace(". ", ".")
        for attr in _FORBIDDEN_ATTRIBUTES:
            if attr in normalised:
                offenders.append(f"{path.name}: code uses {attr!r}")
        for name in _FORBIDDEN_CALL_NAMES:
            if f"{name} (" in code or f"{name}(" in normalised:
                offenders.append(f"{path.name}: code calls {name}()")
    assert not offenders, "forbidden execution primitives in code:\n" + "\n".join(
        offenders
    )


def test_no_forbidden_imports_or_calls_in_ast() -> None:
    """AST-level check: no import of subprocess/pty and no eval/exec/compile call.

    Parsing the AST catches forms a token scan could miss, e.g.
    ``import subprocess as sp`` or ``from os import system``.
    """
    offenders: list[str] = []
    for path in _python_files():
        tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for alias in node.names:
                    root = alias.name.split(".")[0]
                    if root in _FORBIDDEN_MODULES:
                        offenders.append(f"{path.name}: imports {alias.name}")
            elif isinstance(node, ast.ImportFrom):
                module = (node.module or "").split(".")[0]
                if module in _FORBIDDEN_MODULES:
                    offenders.append(f"{path.name}: imports from {node.module}")
                if module == "os":
                    for alias in node.names:
                        if alias.name in {"system", "popen"} or alias.name.startswith(
                            ("exec", "spawn")
                        ):
                            offenders.append(f"{path.name}: imports os.{alias.name}")
            elif isinstance(node, ast.Call):
                func = node.func
                if isinstance(func, ast.Name) and func.id in _FORBIDDEN_CALL_NAMES:
                    offenders.append(f"{path.name}: calls {func.id}()")
                # Catch attribute calls like os.system(...) / pickle.loads(...).
                if isinstance(func, ast.Attribute) and isinstance(func.value, ast.Name):
                    dotted = f"{func.value.id}.{func.attr}"
                    if dotted in _FORBIDDEN_ATTRIBUTES or (
                        func.value.id == "os"
                        and func.attr.startswith(("exec", "spawn", "system", "popen"))
                    ):
                        offenders.append(f"{path.name}: calls {dotted}()")
    assert not offenders, "forbidden imports/calls found:\n" + "\n".join(offenders)


def test_fake_shell_module_imports_no_process_module() -> None:
    """The fake shell must import no process/execution module at all.

    fake_shell.py is the module most directly exposed to attacker input, so it
    gets an extra explicit assertion.
    """
    fake_shell = _PKG / "fake_shell.py"
    tree = ast.parse(fake_shell.read_text(encoding="utf-8"))
    imported_roots: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            imported_roots.update(a.name.split(".")[0] for a in node.names)
        elif isinstance(node, ast.ImportFrom):
            if node.module:
                imported_roots.add(node.module.split(".")[0])
    assert "subprocess" not in imported_roots
    assert "pty" not in imported_roots
    assert "multiprocessing" not in imported_roots


def test_no_attacker_input_is_unpickled() -> None:
    """No source file may call pickle.load/loads (unpickling is code execution)."""
    offenders: list[str] = []
    for path in _python_files():
        tree = ast.parse(path.read_text(encoding="utf-8"))
        for node in ast.walk(tree):
            if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute):
                if (
                    isinstance(node.func.value, ast.Name)
                    and node.func.value.id == "pickle"
                    and node.func.attr in {"load", "loads"}
                ):
                    offenders.append(f"{path.name}: calls pickle.{node.func.attr}()")
    assert not offenders, "unpickling found:\n" + "\n".join(offenders)
