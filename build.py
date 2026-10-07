#!/usr/bin/env python3
"""Build Warp executables with PyInstaller.

Produces two variants for the current OS:
  - GUI  (no console window)      -> dist/warp[.exe]
  - CLI  (console / terminal)     -> dist/warp-cli[.exe]

PyInstaller cannot cross-compile, so run this script once on Linux and once
on Windows to get binaries for both platforms.

Usage:
    python build.py            # build both GUI and CLI
    python build.py --gui      # build only the GUI variant
    python build.py --cli      # build only the CLI variant
    python build.py --clean    # remove build/ and dist/ first
"""
import argparse
import os
import shutil
import subprocess
import sys

ROOT = os.path.dirname(os.path.abspath(__file__))
ENTRY = os.path.join(ROOT, "main.py")
MCP_ENTRY = os.path.join(ROOT, "mcp_server.py")
ICON = os.path.join(ROOT, "app_icon.ico")
IS_WINDOWS = os.name == "nt"

# On Windows the icon/add-data separator is ';', on Linux/macOS it's ':'.
DATA_SEP = ";" if IS_WINDOWS else ":"

# fastmcp drags in a web stack PyInstaller can't fully trace on its own; these
# make the frozen warp-mcp binaries actually import and run.
MCP_COLLECT = ["fastmcp", "mcp", "uvicorn", "starlette", "pydantic", "pydantic_core"]
MCP_METADATA = ["fastmcp", "mcp"]  # fastmcp reads its version via importlib.metadata


def _pip_install(*pkgs):
    subprocess.run([sys.executable, "-m", "pip", "install", "--quiet", *pkgs], check=True)


def ensure_mcp_deps():
    """Make sure fastmcp (and typer, which PyInstaller imports while scanning
    mcp.cli at build time) are importable before an MCP build."""
    try:
        import fastmcp  # noqa: F401
    except ImportError:
        print("installing fastmcp ...")
        _pip_install("fastmcp")
    try:
        import typer  # noqa: F401 - only needed so collect-submodules can scan mcp.cli
    except ImportError:
        print("installing typer (build-time dependency of mcp.cli) ...")
        _pip_install("typer")


def run_pyinstaller(name, windowed):
    """Invoke PyInstaller for one variant."""
    args = [
        sys.executable, "-m", "PyInstaller",
        "--noconfirm",
        "--clean",
        "--onefile",
        "--name", name,
        "--add-data", f"{ICON}{DATA_SEP}.",
        "--windowed" if windowed else "--console",
    ]
    # PyInstaller only supports embedding an icon on Windows and macOS.
    if IS_WINDOWS or sys.platform == "darwin":
        args += ["--icon", ICON]
    if not IS_WINDOWS:
        # Smaller binaries on Linux/macOS.
        args += ["--strip"]
    args.append(ENTRY)

    print(f"\n=== Building {name} ({'GUI' if windowed else 'CLI'}) ===")
    print(" ".join(args))
    subprocess.run(args, check=True, cwd=ROOT)


def run_pyinstaller_mcp(name, windowed):
    """Invoke PyInstaller for one MCP variant (warp-mcp / warp-mcp-gui)."""
    args = [
        sys.executable, "-m", "PyInstaller",
        "--noconfirm",
        "--clean",
        "--onefile",
        "--name", name,
        "--windowed" if windowed else "--console",
    ]
    for pkg in MCP_COLLECT:
        args += ["--collect-all", pkg]
    for pkg in MCP_METADATA:
        args += ["--copy-metadata", pkg]
    if IS_WINDOWS or sys.platform == "darwin":
        args += ["--icon", ICON]
    if not IS_WINDOWS:
        args += ["--strip"]
    args.append(MCP_ENTRY)

    print(f"\n=== Building {name} ({'GUI' if windowed else 'headless'}) ===")
    print(" ".join(args))
    subprocess.run(args, check=True, cwd=ROOT)


def main():
    parser = argparse.ArgumentParser(description="Build Warp executables.")
    parser.add_argument("--gui", action="store_true", help="Build only the GUI variant.")
    parser.add_argument("--cli", action="store_true", help="Build only the CLI variant.")
    parser.add_argument("--mcp", action="store_true",
                        help="Build the MCP server variants (warp-mcp + warp-mcp-gui) instead.")
    parser.add_argument("--clean", action="store_true", help="Remove build/ and dist/ first.")
    ns = parser.parse_args()

    entry = MCP_ENTRY if ns.mcp else ENTRY
    if not os.path.exists(entry):
        sys.exit(f"error: entry point not found: {entry}")

    if shutil.which("pyinstaller") is None:
        try:
            import PyInstaller  # noqa: F401
        except ImportError:
            sys.exit("error: PyInstaller is not installed. Run: pip install pyinstaller")

    if ns.clean:
        for d in ("build", "dist"):
            p = os.path.join(ROOT, d)
            if os.path.isdir(p):
                print(f"removing {p}")
                shutil.rmtree(p)

    if ns.mcp:
        ensure_mcp_deps()
        # --gui / --cli select a subset; default builds both MCP variants.
        build_gui = ns.gui or not ns.cli
        build_headless = ns.cli or not ns.gui
        if build_headless:
            run_pyinstaller_mcp("warp-mcp", windowed=False)
        if build_gui:
            run_pyinstaller_mcp("warp-mcp-gui", windowed=True)
        print(f"\nDone. Binaries are in: {os.path.join(ROOT, 'dist')}")
        return

    build_gui = ns.gui or not ns.cli
    build_cli = ns.cli or not ns.gui

    if build_gui:
        run_pyinstaller("warp", windowed=True)
    if build_cli:
        run_pyinstaller("warp-cli", windowed=False)

    print(f"\nDone. Binaries are in: {os.path.join(ROOT, 'dist')}")


if __name__ == "__main__":
    main()
