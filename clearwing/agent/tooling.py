from __future__ import annotations

import asyncio
import inspect
from collections.abc import Callable
from contextlib import contextmanager
from contextvars import ContextVar
from dataclasses import dataclass, field
from typing import Any

from clearwing.llm.native import NativeToolSpec

_TOOL_ACTIVE: ContextVar[bool] = ContextVar("_TOOL_ACTIVE", default=False)
_TOOL_RESUME_DECISION: ContextVar[object] = ContextVar("_TOOL_RESUME_DECISION", default=Ellipsis)


class InterruptRequest(RuntimeError):
    def __init__(self, prompt: str) -> None:
        super().__init__(prompt)
        self.prompt = prompt


def interrupt(prompt: str) -> bool:
    if not _TOOL_ACTIVE.get():
        return False
    decision = _TOOL_RESUME_DECISION.get()
    if decision is Ellipsis:
        raise InterruptRequest(prompt)
    return bool(decision)


@contextmanager
def tool_execution_context(*, resume_decision: object = Ellipsis):
    token_active = _TOOL_ACTIVE.set(True)
    token_decision = _TOOL_RESUME_DECISION.set(resume_decision)
    try:
        yield
    finally:
        _TOOL_RESUME_DECISION.reset(token_decision)
        _TOOL_ACTIVE.reset(token_active)


class _ArgsSchema:
    def __init__(self, schema: dict[str, Any]) -> None:
        self._schema = schema

    def schema(self) -> dict[str, Any]:
        return self._schema

    def model_json_schema(self) -> dict[str, Any]:
        return self._schema


@dataclass
class AgentTool:
    func: Callable[..., Any]
    name: str
    description: str
    input_schema: dict[str, Any]
    args_schema: _ArgsSchema = field(init=False)

    def __post_init__(self) -> None:
        self.args_schema = _ArgsSchema(self.input_schema)

    def __call__(self, *args: Any, **kwargs: Any) -> Any:
        return self.func(*args, **kwargs)

    async def ainvoke(self, arguments: dict[str, Any] | None = None, /, **kwargs: Any) -> Any:
        params = _normalize_arguments(arguments, kwargs)
        with tool_execution_context():
            if inspect.iscoroutinefunction(self.func):
                return await self.func(**params)
            return await asyncio.to_thread(self.func, **params)

    def invoke(self, arguments: dict[str, Any] | None = None, /, **kwargs: Any) -> Any:
        params = _normalize_arguments(arguments, kwargs)
        try:
            asyncio.get_running_loop()
        except RuntimeError:
            return asyncio.run(self.ainvoke(params))
        return self.ainvoke(params)

    def with_resume_decision(self, decision: bool) -> Callable[[dict[str, Any]], Any]:
        async def runner(arguments: dict[str, Any]) -> Any:
            with tool_execution_context(resume_decision=decision):
                if inspect.iscoroutinefunction(self.func):
                    return await self.func(**arguments)
                return await asyncio.to_thread(self.func, **arguments)

        return runner


def tool(func: Callable[..., Any] | None = None, **decorator_kwargs: Any):
    def wrap(fn: Callable[..., Any]) -> AgentTool:
        name = decorator_kwargs.get("name") or fn.__name__
        description = decorator_kwargs.get("description") or inspect.getdoc(fn) or ""
        return AgentTool(
            func=fn,
            name=name,
            description=description,
            input_schema=_build_schema(fn),
        )

    if func is None:
        return wrap
    return wrap(func)


def as_native_tool_spec(tool_obj: Any) -> NativeToolSpec:
    if isinstance(tool_obj, NativeToolSpec):
        return tool_obj
    if isinstance(tool_obj, AgentTool):
        return NativeToolSpec(
            name=tool_obj.name,
            description=tool_obj.description,
            schema=tool_obj.input_schema,
            handler=tool_obj.func,
        )
    if all(hasattr(tool_obj, attr) for attr in ("name", "description")):
        schema = getattr(tool_obj, "input_schema", None)
        if not isinstance(schema, dict):
            args_schema = getattr(tool_obj, "args_schema", None)
            if args_schema is not None and hasattr(args_schema, "schema"):
                schema = args_schema.schema()
            elif args_schema is not None and hasattr(args_schema, "model_json_schema"):
                schema = args_schema.model_json_schema()
        if not isinstance(schema, dict):
            schema = {"type": "object", "properties": {}}
        handler = getattr(tool_obj, "func", None) or getattr(tool_obj, "invoke", None) or tool_obj
        return NativeToolSpec(
            name=str(tool_obj.name),
            description=str(getattr(tool_obj, "description", "") or ""),
            schema=schema,
            handler=handler,
        )
    raise TypeError(f"Unsupported tool object: {tool_obj!r}")


def ensure_agent_tool(tool_obj: Any) -> NativeToolSpec:
    return as_native_tool_spec(tool_obj)


def _normalize_arguments(
    arguments: dict[str, Any] | None,
    kwargs: dict[str, Any],
) -> dict[str, Any]:
    params = dict(arguments or {})
    params.update(kwargs)
    return params


def _build_schema(fn: Callable[..., Any]) -> dict[str, Any]:
    signature = inspect.signature(fn)
    properties: dict[str, Any] = {}
    required: list[str] = []

    for name, parameter in signature.parameters.items():
        if parameter.kind not in (
            inspect.Parameter.POSITIONAL_OR_KEYWORD,
            inspect.Parameter.KEYWORD_ONLY,
        ):
            continue
        properties[name] = _schema_for_annotation(parameter.annotation)
        if parameter.default is inspect._empty:
            required.append(name)

    schema: dict[str, Any] = {
        "type": "object",
        "properties": properties,
        "additionalProperties": False,
    }
    if required:
        schema["required"] = required
    return schema


def _schema_for_annotation(annotation: Any) -> dict[str, Any]:
    origin = getattr(annotation, "__origin__", None)
    args = getattr(annotation, "__args__", ())

    if annotation in {str, inspect._empty}:
        return {"type": "string"}
    if annotation is int:
        return {"type": "integer"}
    if annotation is float:
        return {"type": "number"}
    if annotation is bool:
        return {"type": "boolean"}
    if annotation in {dict, Any} or origin is dict:
        return {"type": "object"}
    if annotation is list or origin is list:
        item_annotation = args[0] if args else Any
        return {"type": "array", "items": _schema_for_annotation(item_annotation)}
    if origin is tuple:
        return {"type": "array"}
    if origin is Callable:
        return {"type": "string"}
    if origin is None and hasattr(annotation, "__supertype__"):
        return _schema_for_annotation(annotation.__supertype__)
    if origin is None and getattr(annotation, "__module__", "") == "typing":
        return {"type": "string"}
    return {"type": "string"}
