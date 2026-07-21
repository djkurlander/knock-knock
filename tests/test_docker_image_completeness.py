"""Guard against shipping a crash-looping Docker image.

The Dockerfile COPYs root-level Python modules with an explicit (selective) list, not `COPY . .`.
When `self_redaction.py` was extracted as a module that `monitor.py` imports but wasn't added to
that list, the built image omitted it and every Docker deployment crash-looped with
`ModuleNotFoundError: No module named 'self_redaction'` — while the ordinary unit tests passed,
because they import from the checkout where the file *is* present.

This test closes that gap: it parses the Dockerfile's COPY list and the container entrypoints'
imports, and fails if any root module an entrypoint imports isn't shipped. It runs in the same
CI step (`Run unit tests`) that gates the image build, so a missing module fails CI before push.

(Subpackages like honeypots/ and protocols/ are COPY'd whole-directory, so only the selectively
listed *root* .py modules are at risk — which is exactly what this checks.)
"""
import ast
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
ENTRYPOINTS = ("monitor.py", "main.py")   # what the container actually runs


def _root_modules():
    """Importable top-level module names (root-level .py files)."""
    return {p.stem for p in ROOT.glob("*.py")}


def _dockerfile_copied_py():
    """Root .py module names the Dockerfile COPYs (line continuations joined)."""
    text = (ROOT / "Dockerfile").read_text().replace("\\\n", " ")
    copied = set()
    for line in text.splitlines():
        line = line.strip()
        if line.startswith("COPY "):
            for tok in line[len("COPY "):].split():
                if tok.endswith(".py"):
                    copied.add(Path(tok).stem)
    return copied


def _root_imports_of(pyfile, root_mods):
    tree = ast.parse((ROOT / pyfile).read_text())
    found = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                base = alias.name.split(".")[0]
                if base in root_mods:
                    found.add(base)
        elif isinstance(node, ast.ImportFrom) and node.level == 0 and node.module:
            base = node.module.split(".")[0]
            if base in root_mods:
                found.add(base)
    return found


def test_dockerfile_ships_all_root_modules_the_container_imports():
    root_mods = _root_modules()
    copied = _dockerfile_copied_py()
    needed = set()
    for entry in ENTRYPOINTS:
        needed |= _root_imports_of(entry, root_mods)
    missing = needed - copied
    assert not missing, (
        "Dockerfile COPY is missing root module(s) imported by the container entrypoints "
        f"{ENTRYPOINTS}: {sorted(missing)}. Add them to the Dockerfile COPY line, or the built "
        "image will crash-loop with ModuleNotFoundError."
    )
