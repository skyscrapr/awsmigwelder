import pytest
import sys
import subprocess
import shutil

def test_cli_module_help():
    for mod in ("migwelder", "awsmigwelder"):
        proc = subprocess.run([sys.executable, "-m", mod, "--help"], stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
        if proc.returncode != 0 and "No module named" in proc.stdout:
            pytest.skip(f"Module not importable for {mod}")
        assert proc.returncode in (0, 2)
        out = proc.stdout.lower()
        assert "usage" in out or "options" in out

def test_cli_console_script():
    exe = shutil.which("awsmigwelder")
    if not exe:
        pytest.skip("console script 'awsmigwelder' not installed (pip install -e .).")
    proc = subprocess.run([exe, "--help"], stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
    assert proc.returncode in (0, 2)
    out = proc.stdout.lower()
    assert "usage" in out or "options" in out
