"""Run PowerShell inside the lab Windows VM through vmrun and collect its output.

Credentials and the VM encryption password are read from the lab Keys folder;
nothing is printed or written outside it. Usage:

    python tools/validation/vm/guest.py ps "Get-ComputerInfo | Select OsBuildNumber"
    python tools/validation/vm/guest.py put LOCAL_PATH GUEST_PATH
    python tools/validation/vm/guest.py get GUEST_PATH LOCAL_PATH
"""

from __future__ import annotations

import os
import subprocess
import sys
import tempfile
import uuid
from pathlib import Path

VMRUN = Path(os.environ.get("VMRUN", r"C:\Program Files (x86)\VMware\VMware Workstation\vmrun.exe"))
VMX = Path(os.environ.get("PANO_WIN_VMX", r"C:\PanopticonLab\VMs\PANO-NEW-WIN-01\PANO-NEW-WIN-01.vmx"))
KEYS = Path(os.environ.get("PANO_KEYS", r"C:\PanopticonLab\Keys"))
GUEST_WORK = r"C:\PanoValidation"


def _credentials() -> list[str]:
    vm_password = (KEYS / "PANO-NEW-WIN-01-vm-encryption.txt").read_text().strip()
    user, password = (KEYS / "PANO-NEW-WIN-01-guest.txt").read_text().split()[:2]
    return ["-T", "ws", "-vp", vm_password, "-gu", user, "-gp", password]


def vmrun(*arguments: str, timeout: int = 600) -> subprocess.CompletedProcess:
    try:
        return subprocess.run([str(VMRUN), *_credentials(), *arguments], capture_output=True,
                              text=True, timeout=timeout, check=False)
    except subprocess.TimeoutExpired:
        # TimeoutExpired includes the complete argv, including guest credentials.
        # Never put that exception (or its chained context) in evidence or logs.
        raise TimeoutError(f"VMware operation {arguments[0]} timed out") from None


def put(local: str, guest: str) -> None:
    result = vmrun("copyFileFromHostToGuest", str(VMX), local, guest)
    if result.returncode != 0:
        raise RuntimeError(f"copy to guest failed: {result.stdout.strip()} {result.stderr.strip()}")


def get(guest: str, local: str) -> None:
    result = vmrun("copyFileFromGuestToHost", str(VMX), guest, local)
    if result.returncode != 0:
        raise RuntimeError(f"copy from guest failed: {result.stdout.strip()} {result.stderr.strip()}")


def ps(script: str, timeout: int = 900) -> tuple[int, str]:
    """Run a PowerShell script elevated in the guest; return (exit code, combined output)."""
    vmrun("createDirectoryInGuest", str(VMX), GUEST_WORK)
    token = uuid.uuid4().hex[:10]
    guest_script, guest_out = rf"{GUEST_WORK}\run-{token}.ps1", rf"{GUEST_WORK}\run-{token}.out"
    # Redirect at the cmd level so parse errors and native stderr are captured too.
    wrapped = f"$ErrorActionPreference='Continue'\n{script}\nexit $LASTEXITCODE\n"
    with tempfile.TemporaryDirectory() as scratch:
        local_script = Path(scratch) / "run.ps1"
        local_script.write_text(wrapped, encoding="utf-8-sig")
        put(str(local_script), guest_script)
        result = vmrun("runProgramInGuest", str(VMX), r"C:\Windows\System32\cmd.exe",
                       f"/c powershell -NoProfile -ExecutionPolicy Bypass -File {guest_script} "
                       f"> {guest_out} 2>&1", timeout=timeout)
        local_out = Path(scratch) / "run.out"
        try:
            get(guest_out, str(local_out))
            output = local_out.read_text(encoding="utf-16", errors="replace") if local_out.read_bytes()[:2] in (
                b"\xff\xfe", b"\xfe\xff") else local_out.read_text(encoding="utf-8", errors="replace")
        except RuntimeError as error:
            output = f"<no output: {error}>"
    vmrun("deleteFileInGuest", str(VMX), guest_script)
    code = result.returncode
    return code, output


def main(argv: list[str]) -> int:
    if len(argv) >= 3 and argv[1] == "ps":
        code, output = ps(argv[2])
        print(output.rstrip())
        return code
    if len(argv) == 4 and argv[1] in ("put", "get"):
        (put if argv[1] == "put" else get)(argv[2], argv[3])
        return 0
    print(__doc__)
    return 2


if __name__ == "__main__":
    sys.exit(main(sys.argv))
