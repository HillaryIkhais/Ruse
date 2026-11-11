#!/usr/bin/env python3
"""PTY driver — run `hermes chat -q --oneshot` and answer prompts programmatically.

Captures the full stdout/stderr transcript. Keeps an open pseudo-terminal
to Hermes so interactive approval cards and initial config prompts are
answered with Enter until "Type your message" appears, then sends the
user prompt and exits.
"""

from __future__ import annotations

import os
import pty
import select
import signal
import subprocess
import sys
import tempfile
import threading
import time
from pathlib import Path


class HermesPty:
    def __init__(self, cmd: list, env: dict, home: Path):
        self.cmd = cmd
        self.env = env
        self.home = home
        self.fd = None
        self.pid = None
        self.stdout = []
        self.stderr = []
        self._running = False

    def run(self, user_message: str, timeout: float = 90.0) -> dict:
        """Run hermes with the message, return transcript."""
        self.fd, child_fd = pty.openpty()
        self.pid = os.fork()
        if self.pid == 0:
            # child
            os.close(self.fd)
            os.dup2(child_fd, 0)
            os.dup2(child_fd, 1)
            os.dup2(child_fd, 2)
            os.close(child_fd)
            os.setsid()
            os.execvpe(self.cmd[0], self.cmd, self.env)
            os._exit(1)
        os.close(child_fd)
        self._running = True
        self.stdout, self.stderr = [], []
        start = time.time()

        def read_loop():
            buf = b""
            while self._running and time.time() - start < timeout:
                try:
                    r, _, _ = select.select([self.fd], [], [], 0.1)
                    if not r:
                        continue
                    chunk = os.read(self.fd, 4096)
                    if not chunk:
                        break
                    buf += chunk
                    while b"\n" in buf:
                        line, buf = buf.split(b"\n", 1)
                        self.stdout.append(line.decode("utf-8", "replace"))
                except OSError:
                    break
            self._running = False

        t = threading.Thread(target=read_loop, daemon=True)
        t.start()

        # wait for "Type your message" or similar prompt, then send the message
        prompt_seen = False
        while time.time() - start < timeout:
            tail = "\n".join(self.stdout[-20:])
            if "Type your message" in tail or "your message" in tail.lower():
                prompt_seen = True
                break
            if "Failed to" in tail or "Error:" in tail:
                break
            time.sleep(0.3)

        if prompt_seen:
            os.write(self.fd, (user_message + "\n").encode())
        else:
            # no prompt: maybe --oneshot doesn't show it; just try
            os.write(self.fd, (user_message + "\n").encode())

        # wait for completion or timeout
        while self._running and time.time() - start < timeout:
            tail = "\n".join(self.stdout[-5:])
            if "💬" in tail or "assistant" in tail.lower() or "result" in tail.lower():
                time.sleep(1.5)
                break
            time.sleep(0.3)

        self._running = False
        t.join(timeout=2)
        try:
            os.killpg(os.getpgid(self.pid), signal.SIGKILL)
        except Exception:
            pass
        try:
            os.waitpid(self.pid, 0)
        except Exception:
            pass

        return {"stdout": "\n".join(self.stdout),
                "stderr": "\n".join(self.stderr),
                "prompt_seen": prompt_seen,
                "duration": time.time() - start}


def main():
    import argparse
    parser = argparse.ArgumentParser()
    parser.add_argument("--bin", default="hermes")
    parser.add_argument("--home", required=True)
    parser.add_argument("--msg", required=True)
    parser.add_argument("--timeout", type=float, default=90)
    args = parser.parse_args()

    home = Path(args.home).expanduser()
    home.mkdir(parents=True, exist_ok=True)

    env = dict(os.environ)
    env.update({"HERMES_HOME": str(home),
                "HOME": str(home.parent),  # prevent ~/.config pollution
                "TERM": "dumb",
                "PYTHONUNBUFFERED": "1"})

    driver = HermesPty([args.bin], env, home)
    res = driver.run(args.msg, args.timeout)
    print("--- STDOUT ---")
    print(res["stdout"])
    print("--- STDERR ---")
    print(res["stderr"])
    print(f"prompt_seen: {res['prompt_seen']}, duration: {res['duration']:.1f}s")
    return 0 if res["prompt_seen"] else 1


if __name__ == "__main__":
    sys.exit(main())