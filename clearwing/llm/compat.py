from __future__ import annotations

import asyncio
import inspect
import json
from typing import Any

from pydantic import BaseModel, ValidationError

from .chat import HumanMessage, SystemMessage, extract_text_content
from .native import extract_json_array, extract_json_object


def _get_supported_method(obj: Any, name: str) -> Any | None:
    try:
        inspect.getattr_static(type(obj), name)
    except AttributeError:
        mock_children = getattr(obj, "_mock_children", None)
        if not isinstance(mock_children, dict) or name not in mock_children:
            return None

    method = getattr(obj, name, None)
    return method if callable(method) else None


def _validate_schema_text(schema_model: type[BaseModel], text: str) -> BaseModel:
    try:
        return schema_model.model_validate_json(text)
    except ValidationError:
        parsed_json = json.loads(text)
        results_field = schema_model.model_fields.get("results")
        if results_field is None or not isinstance(parsed_json, list):
            raise
        return schema_model.model_validate({"results": parsed_json})


def _resolve_sync_result(result: Any) -> Any:
    if not inspect.isawaitable(result):
        return result
    try:
        asyncio.get_running_loop()
    except RuntimeError:
        return asyncio.run(result)
    if inspect.iscoroutine(result):
        result.close()
    raise RuntimeError("invoke_text_compat cannot await while an event loop is running")


def invoke_text_compat(llm: Any, *, system: str, user: str) -> str:
    """Call either the native client or a sync/mock LLM used by legacy tests."""
    aask_text = _get_supported_method(llm, "aask_text")
    if aask_text is not None:
        response = _resolve_sync_result(
            aask_text(
                system=system,
                user=user,
            )
        )
        text = getattr(response, "text", None)
        if isinstance(text, str):
            return text
        return extract_text_content(getattr(response, "content", ""))

    invoke = _get_supported_method(llm, "invoke")
    if invoke is not None:
        response = invoke(
            [
                SystemMessage(content=system),
                HumanMessage(content=user),
            ]
        )
        text = getattr(response, "text", None)
        if isinstance(text, str):
            return text
        return extract_text_content(getattr(response, "content", ""))

    chat = _get_supported_method(llm, "chat")
    if chat is not None:
        response = chat(
            messages=[{"role": "user", "content": user}],
            system=system,
        )
        text = getattr(response, "text", None)
        if isinstance(text, str):
            return text
        return extract_text_content(getattr(response, "content", ""))

    raise TypeError(f"Unsupported LLM object: {llm!r}")


async def aask_json_compat(
    llm: Any,
    *,
    system: str,
    user: str,
    expect: str = "object",
    schema_model: type[BaseModel] | None = None,
    schema_name: str | None = None,
    schema_description: str | None = None,
) -> tuple[Any, Any]:
    aask_json = _get_supported_method(llm, "aask_json")
    if aask_json is not None:
        result = aask_json(
            system=system,
            user=user,
            expect=expect,
            schema_model=schema_model,
            schema_name=schema_name,
            schema_description=schema_description,
        )
        if inspect.isawaitable(result):
            return await result
        return result

    text = invoke_text_compat(llm, system=system, user=user)
    if schema_model is not None:
        parsed_model = _validate_schema_text(schema_model, text)
        if schema_model.__pydantic_root_model__:
            return parsed_model.root, None
        return parsed_model.model_dump(), None
    if expect == "array":
        return extract_json_array(text), None
    return extract_json_object(text), None
