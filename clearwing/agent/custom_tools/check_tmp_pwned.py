"""Auto-generated custom tool: check_tmp_pwned"""
import asyncio
import json
import re
import socket
import subprocess

from clearwing.agent.tooling import tool


@tool
async def check_tmp_pwned() -> str:
    """Check whether /tmp/pwned exists on the local filesystem and return metadata."""
    import os, json
    path = '/tmp/pwned'
    exists = os.path.exists(path)
    result = {'path': path, 'exists': exists}
    if exists:
        st = os.stat(path)
        result.update({'size': st.st_size, 'mode': oct(st.st_mode & 0o777), 'mtime': st.st_mtime})
    return result
