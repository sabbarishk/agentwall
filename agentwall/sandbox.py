import asyncio
import inspect
import textwrap
from typing import Any, Callable


class DockerSandbox:
    def __init__(self, image: str = "python:3.11-slim", timeout: int = 30):
        self._image = image
        self._timeout = timeout

    async def execute(self, fn: Callable, *args, **kwargs) -> Any:
        source = textwrap.dedent(inspect.getsource(fn))
        call_args = ", ".join(
            [repr(a) for a in args] + [f"{k}={repr(v)}" for k, v in kwargs.items()]
        )
        script = f"{source}\nresult = {fn.__name__}({call_args})\nprint(result)"

        proc = await asyncio.create_subprocess_exec(
            "docker", "run", "--rm",
            "--network", "none",
            "--memory", "128m",
            "--cpus", "0.5",
            self._image,
            "python3", "-c", script,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )

        try:
            stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=self._timeout)
        except asyncio.TimeoutError:
            proc.kill()
            raise RuntimeError(f"Sandbox execution timed out after {self._timeout}s")

        if proc.returncode != 0:
            raise RuntimeError(f"Sandbox error: {stderr.decode().strip()}")

        return stdout.decode().strip()
