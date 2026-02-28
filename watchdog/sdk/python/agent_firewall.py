"""
Agent-WatchDog Python SDK — Non-invasive Firewall Wrapper

Wrap ANY tool call with a security check against the WatchDog
firewall. If the call is blocked, a SecurityException is raised
BEFORE the tool ever executes.

Usage:
    from agent_firewall import AgentFirewall, SecurityException

    firewall = AgentFirewall(
        base_url="http://localhost:3001",
        agent_id="my-agent",
        user_id="user-42",
    )

    # Option 1: Decorator
    @firewall.guard("file_read")
    def read_file(path: str) -> str:
        return open(path).read()

    # Option 2: Context manager
    with firewall.check("shell_exec", {"cmd": "ls -la"}):
        os.system("ls -la")

    # Option 3: Explicit check
    result = firewall.evaluate("http_request", {"url": "https://example.com"})
    if result.allowed:
        requests.get("https://example.com")
"""

from __future__ import annotations

import functools
import json
import time
from dataclasses import dataclass, field
from typing import Any, Callable, Optional
from urllib import request as urllib_request
from urllib.error import URLError


class SecurityException(Exception):
    """Raised when the firewall blocks a tool call."""

    def __init__(
        self,
        tool: str,
        reason: str,
        risk_score: float,
        matched_rule: Optional[str] = None,
    ):
        self.tool = tool
        self.reason = reason
        self.risk_score = risk_score
        self.matched_rule = matched_rule
        super().__init__(
            f"🛑 BLOCKED: tool={tool} reason={reason} "
            f"risk={risk_score:.1f} rule={matched_rule}"
        )


@dataclass
class RiskBreakdown:
    """Detailed risk score breakdown."""
    total: float = 0.0
    tool_weight: float = 0.0
    arg_danger: float = 0.0
    frequency_penalty: float = 0.0
    details: list[str] = field(default_factory=list)


@dataclass
class EvalResult:
    """Result of a firewall evaluation."""
    decision: str = "allow"
    allowed: bool = True
    risk_score: float = 0.0
    risk_breakdown: RiskBreakdown = field(default_factory=RiskBreakdown)
    reason: str = ""
    matched_rule: Optional[str] = None
    dry_run: bool = False


class AgentFirewall:
    """
    Non-invasive firewall wrapper for AI agent tool calls.

    Sends a pre-check to the WatchDog firewall proxy before every
    tool execution. If the firewall returns "block", raises
    SecurityException — the tool never runs.

    Args:
        base_url: WatchDog firewall proxy URL (default: http://localhost:3001)
        agent_id: Unique identifier for this agent
        user_id: User/session owner
        session_id: Optional session/conversation ID
        fail_open: If True, allow tool calls when the firewall is unreachable.
                   If False, block all calls when the firewall is down.
        timeout: HTTP request timeout in seconds
    """

    def __init__(
        self,
        base_url: str = "http://localhost:3001",
        agent_id: str = "default-agent",
        user_id: str = "default-user",
        session_id: Optional[str] = None,
        fail_open: bool = True,
        timeout: float = 2.0,
    ):
        self.base_url = base_url.rstrip("/")
        self.agent_id = agent_id
        self.user_id = user_id
        self.session_id = session_id
        self.fail_open = fail_open
        self.timeout = timeout

    def evaluate(self, tool: str, args: Any = None) -> EvalResult:
        """
        Evaluate a tool call against the firewall policy.

        Returns an EvalResult. Does NOT raise on block — call
        `evaluate_or_raise()` for that behavior.
        """
        if args is None:
            args = {}
        if not isinstance(args, dict):
            args = {"value": args}

        payload = {
            "agent_id": self.agent_id,
            "user_id": self.user_id,
            "tool": tool,
            "args": args,
        }
        if self.session_id:
            payload["session_id"] = self.session_id

        try:
            data = json.dumps(payload).encode("utf-8")
            req = urllib_request.Request(
                f"{self.base_url}/v1/intercept",
                data=data,
                headers={"Content-Type": "application/json"},
                method="POST",
            )
            with urllib_request.urlopen(req, timeout=self.timeout) as resp:
                body = json.loads(resp.read().decode("utf-8"))
                return self._parse_response(body)

        except URLError as e:
            # Check if it's a 403 response (blocked)
            if hasattr(e, "code") and e.code == 403:
                body = json.loads(e.read().decode("utf-8"))
                return self._parse_response(body)

            # Firewall unreachable
            if self.fail_open:
                return EvalResult(
                    decision="allow",
                    allowed=True,
                    reason=f"Firewall unreachable (fail-open): {e}",
                )
            else:
                return EvalResult(
                    decision="block",
                    allowed=False,
                    reason=f"Firewall unreachable (fail-closed): {e}",
                )

    def evaluate_or_raise(self, tool: str, args: Any = None) -> EvalResult:
        """
        Evaluate a tool call. Raises SecurityException if blocked.
        """
        result = self.evaluate(tool, args)
        if not result.allowed:
            raise SecurityException(
                tool=tool,
                reason=result.reason,
                risk_score=result.risk_score,
                matched_rule=result.matched_rule,
            )
        return result

    def guard(self, tool_name: str) -> Callable:
        """
        Decorator that wraps a function with a firewall check.

        The function's keyword arguments are sent as the tool args.

        Usage:
            @firewall.guard("file_read")
            def read_file(path: str) -> str:
                return open(path).read()
        """

        def decorator(fn: Callable) -> Callable:
            @functools.wraps(fn)
            def wrapper(*args: Any, **kwargs: Any) -> Any:
                # Build args dict from function arguments
                import inspect

                sig = inspect.signature(fn)
                bound = sig.bind(*args, **kwargs)
                bound.apply_defaults()
                tool_args = dict(bound.arguments)

                self.evaluate_or_raise(tool_name, tool_args)
                return fn(*args, **kwargs)

            return wrapper

        return decorator

    def check(self, tool: str, args: Any = None):
        """
        Context manager for wrapping a code block with a firewall check.

        Usage:
            with firewall.check("shell_exec", {"cmd": "ls"}):
                os.system("ls")
        """
        return _FirewallContext(self, tool, args)

    def _parse_response(self, body: dict) -> EvalResult:
        breakdown = body.get("risk_breakdown", {})
        return EvalResult(
            decision=body.get("decision", "allow"),
            allowed=body.get("allowed", True),
            risk_score=body.get("risk_score", 0.0),
            risk_breakdown=RiskBreakdown(
                total=breakdown.get("total", 0.0),
                tool_weight=breakdown.get("tool_weight", 0.0),
                arg_danger=breakdown.get("arg_danger", 0.0),
                frequency_penalty=breakdown.get("frequency_penalty", 0.0),
                details=breakdown.get("details", []),
            ),
            reason=body.get("reason", ""),
            matched_rule=body.get("matched_rule"),
            dry_run=body.get("dry_run", False),
        )


class _FirewallContext:
    """Context manager for firewall.check()."""

    def __init__(self, firewall: AgentFirewall, tool: str, args: Any):
        self.firewall = firewall
        self.tool = tool
        self.args = args

    def __enter__(self):
        self.firewall.evaluate_or_raise(self.tool, self.args)
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        return False


# ── Convenience for LangChain / LlamaIndex integration ────────

def create_langchain_callback(firewall: AgentFirewall):
    """
    Create a LangChain callback handler that intercepts tool calls.

    Usage:
        from agent_firewall import AgentFirewall, create_langchain_callback

        fw = AgentFirewall(agent_id="langchain-agent")
        cb = create_langchain_callback(fw)

        agent = initialize_agent(tools, llm, callbacks=[cb])
    """
    try:
        from langchain.callbacks.base import BaseCallbackHandler
    except ImportError:
        raise ImportError("langchain is required for create_langchain_callback")

    class WatchDogCallback(BaseCallbackHandler):
        def on_tool_start(self, serialized: dict, input_str: str, **kwargs):
            tool_name = serialized.get("name", "unknown_tool")
            try:
                args = json.loads(input_str)
            except (json.JSONDecodeError, TypeError):
                args = {"input": input_str}

            firewall.evaluate_or_raise(tool_name, args)

    return WatchDogCallback()
