"""Dynamic loader for operator-written competition scripts (`scripts/custom/*.py`).

Allows the team to write a 10-line async function for custom application logic during a live
competition and have AETHER execute it with full scope enforcement, flag validation,
deduplication, and manual inbox tracking.
"""

from __future__ import annotations

import importlib.util
from pathlib import Path

import httpx

from ..attack.exploits.base import ExploitMeta, ExploitPlugin
from .models import ModuleResult, TaskState
from .plugin import ModuleMeta, RunContext


class CustomScriptPlugin(ExploitPlugin):
    """Wraps a Python script defining `async def check_target(host, port, flag_ids, client)`.

    It is a first-class ExploitPlugin so the normal attack engine (prerequisites, scope, flag
    extraction) runs it exactly like a built-in exploit — which is what the sweep / farm loop
    invokes it through.
    """

    meta = ModuleMeta(
        identifier="custom.script._base",
        description="Operator custom script",
        supported_kinds=("web", "http", "https", "tcp"),
        category="exploit",
        timeout=25.0,
    )
    exploit = ExploitMeta(
        prerequisites=("authorized target",),
        expected_result="flag string from custom service flow",
        verification="matches configured flag pattern",
        validated=True,
        research_only=False,
        reference="operator custom script",
    )

    def __init__(self, script_path: str | Path) -> None:
        self.script_path = Path(script_path)
        stem = self.script_path.stem
        self.meta = ModuleMeta(
            identifier=f"custom.script.{stem}",
            description=f"Operator custom script ({self.script_path.name})",
            supported_kinds=("web", "http", "https", "tcp"),
            category="exploit",
            timeout=25.0,
            tags=("custom", stem),
        )

    async def run(self, context: RunContext) -> ModuleResult:
        host = context.target_host or ""
        port = context.target_port or int(context.extra.get("port", 80))
        if context.scope is not None:
            context.scope.enforce(host, port)

        if not self.script_path.is_file():
            return ModuleResult(
                module=self.identifier,
                target=host,
                state=TaskState.FAILED,
                detail=f"script not found: {self.script_path}",
            )

        spec = importlib.util.spec_from_file_location(self.script_path.stem, self.script_path)
        if spec is None or spec.loader is None:
            return ModuleResult(
                module=self.identifier,
                target=host,
                state=TaskState.FAILED,
                detail=f"could not load spec for {self.script_path.name}",
            )
        mod = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(mod)
        fn = getattr(mod, "check_target", None)
        if fn is None:
            return ModuleResult(
                module=self.identifier,
                target=host,
                state=TaskState.FAILED,
                detail=f"{self.script_path.name} must define async def check_target(...)",
            )

        flag_ids: list[str] = list(context.extra.get("flag_ids") or [])
        cookies = context.extra.get("cookies") or None
        headers = context.extra.get("auth_headers") or None
        async with httpx.AsyncClient(
            timeout=self.meta.timeout,
            follow_redirects=True,
            verify=False,
            cookies=cookies,
            headers=headers,
        ) as client:
            raw_outputs = await fn(host, port, flag_ids, client)

        responses: dict[str, str] = {}
        if isinstance(raw_outputs, str):
            responses["out_0"] = raw_outputs
        elif isinstance(raw_outputs, (list, tuple)):
            for idx, item in enumerate(raw_outputs):
                responses[f"out_{idx}"] = str(item)
        elif isinstance(raw_outputs, dict):
            responses = {str(k): str(v) for k, v in raw_outputs.items()}

        return ModuleResult(
            module=self.identifier,
            target=host,
            state=TaskState.SUCCEEDED,
            detail=f"executed {self.script_path.name} ({len(responses)} output(s))",
            data={"responses": responses},
        )


def load_custom_scripts(directory: str | Path = "scripts/custom") -> list[CustomScriptPlugin]:
    """Discover all active operator scripts in `scripts/custom/` (ignoring `example_*` / `_`)."""
    root = Path(directory)
    if not root.is_dir():
        return []
    plugins: list[CustomScriptPlugin] = []
    for p in sorted(root.glob("*.py")):
        if p.name.startswith("_") or p.name.startswith("example_"):
            continue
        plugins.append(CustomScriptPlugin(p))
    return plugins
