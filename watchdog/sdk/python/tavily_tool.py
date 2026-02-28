"""
Agent-WatchDog — Tavily Search Tool (Firewall-Guarded)

A thin wrapper around the Tavily Search API that routes every query
through the WatchDog firewall for policy enforcement and audit logging.

The firewall sees each call as tool="tavily_search" with the query
and parameters in args, so policy rules can:
  - allow/block specific query patterns
  - rate-limit search calls per agent
  - audit all web research activity

Usage:
    from agent_firewall import AgentFirewall
    from tavily_tool import TavilySearchTool

    firewall = AgentFirewall(agent_id="research-agent")
    tavily = TavilySearchTool(api_key="tvly-...", firewall=firewall)

    results = tavily.search("eBPF tracing best practices")
    for r in results:
        print(r["title"], r["url"])

Requirements:
    pip install tavily-python
"""

from __future__ import annotations

import json
import os
from dataclasses import dataclass, field
from typing import Any, Optional

from agent_firewall import AgentFirewall, SecurityException


@dataclass
class TavilySearchResult:
    """A single search result from Tavily."""
    title: str
    url: str
    content: str
    score: float = 0.0
    raw_content: Optional[str] = None

    def __str__(self) -> str:
        return f"[{self.title}]({self.url})\n{self.content[:200]}..."


@dataclass
class TavilySearchResponse:
    """Full response from a Tavily search call."""
    query: str
    results: list[TavilySearchResult] = field(default_factory=list)
    answer: Optional[str] = None
    response_time: float = 0.0

    @property
    def top_result(self) -> Optional[TavilySearchResult]:
        return self.results[0] if self.results else None

    def summary(self) -> str:
        """Return the AI-generated answer or the top result content."""
        if self.answer:
            return self.answer
        if self.results:
            return self.results[0].content
        return "(no results)"


class TavilySearchTool:
    """
    Firewall-guarded Tavily search tool for AI agents.

    Every search call is first checked against the WatchDog firewall.
    If the firewall blocks it (e.g., query contains forbidden patterns,
    rate limit exceeded), a SecurityException is raised BEFORE the
    Tavily API is ever called.

    Args:
        api_key: Tavily API key (or set TAVILY_API_KEY env var)
        firewall: AgentFirewall instance for policy enforcement
        search_depth: "basic" or "advanced" (advanced uses more credits)
        max_results: Number of results to return (1-10)
        include_answer: Whether to include AI-generated answer summary
        include_raw_content: Whether to include full page content
    """

    TOOL_NAME = "tavily_search"

    def __init__(
        self,
        api_key: Optional[str] = None,
        firewall: Optional[AgentFirewall] = None,
        search_depth: str = "basic",
        max_results: int = 5,
        include_answer: bool = True,
        include_raw_content: bool = False,
    ):
        self.api_key = api_key or os.environ.get("TAVILY_API_KEY", "")
        if not self.api_key:
            raise ValueError(
                "Tavily API key required. Pass api_key= or set TAVILY_API_KEY."
            )

        self.firewall = firewall
        self.search_depth = search_depth
        self.max_results = max_results
        self.include_answer = include_answer
        self.include_raw_content = include_raw_content

        # Import tavily client
        try:
            from tavily import TavilyClient
            self._client = TavilyClient(api_key=self.api_key)
        except ImportError:
            raise ImportError(
                "tavily-python is required. Install with: pip install tavily-python"
            )

    def search(
        self,
        query: str,
        search_depth: Optional[str] = None,
        max_results: Optional[int] = None,
        include_domains: Optional[list[str]] = None,
        exclude_domains: Optional[list[str]] = None,
    ) -> TavilySearchResponse:
        """
        Search the web via Tavily, with firewall pre-check.

        Args:
            query: The search query string
            search_depth: Override default search depth
            max_results: Override default max results
            include_domains: Only include results from these domains
            exclude_domains: Exclude results from these domains

        Returns:
            TavilySearchResponse with results and optional AI answer

        Raises:
            SecurityException: If the firewall blocks this search
        """
        depth = search_depth or self.search_depth
        n_results = max_results or self.max_results

        # ── Firewall pre-check ────────────────────────────────────
        tool_args = {
            "query": query,
            "search_depth": depth,
            "max_results": n_results,
        }
        if include_domains:
            tool_args["include_domains"] = include_domains
        if exclude_domains:
            tool_args["exclude_domains"] = exclude_domains

        if self.firewall:
            self.firewall.evaluate_or_raise(self.TOOL_NAME, tool_args)

        # ── Call Tavily API ───────────────────────────────────────
        raw = self._client.search(
            query=query,
            search_depth=depth,
            max_results=n_results,
            include_answer=self.include_answer,
            include_raw_content=self.include_raw_content,
            include_domains=include_domains or [],
            exclude_domains=exclude_domains or [],
        )

        # ── Parse response ────────────────────────────────────────
        results = [
            TavilySearchResult(
                title=r.get("title", ""),
                url=r.get("url", ""),
                content=r.get("content", ""),
                score=r.get("score", 0.0),
                raw_content=r.get("raw_content"),
            )
            for r in raw.get("results", [])
        ]

        return TavilySearchResponse(
            query=query,
            results=results,
            answer=raw.get("answer"),
            response_time=raw.get("response_time", 0.0),
        )

    def quick_answer(self, query: str) -> str:
        """
        Convenience: search and return just the AI-generated answer.

        Falls back to the top result content if no answer is available.
        """
        resp = self.search(query, include_answer=True)
        return resp.summary()


# ── Standalone usage ──────────────────────────────────────────────

if __name__ == "__main__":
    import sys

    if len(sys.argv) < 2:
        print("Usage: python tavily_tool.py <query>")
        print("  Set TAVILY_API_KEY and optionally WATCHDOG_URL env vars")
        sys.exit(1)

    query = " ".join(sys.argv[1:])

    # Create firewall (fail-open if watchdog not running)
    fw = AgentFirewall(
        base_url=os.environ.get("WATCHDOG_URL", "http://localhost:3001"),
        agent_id="tavily-cli",
        user_id="developer",
        fail_open=True,
    )

    tool = TavilySearchTool(firewall=fw)

    print(f"🔍 Searching: {query}")
    print(f"🛡️  Firewall: {fw.base_url}")
    print()

    try:
        response = tool.search(query)

        if response.answer:
            print(f"💡 AI Answer:\n{response.answer}\n")

        print(f"📊 {len(response.results)} results ({response.response_time:.1f}s):\n")

        for i, r in enumerate(response.results, 1):
            print(f"  {i}. {r.title}")
            print(f"     {r.url}")
            print(f"     {r.content[:120]}...")
            print()

    except SecurityException as e:
        print(f"🛑 BLOCKED by WatchDog: {e}")
        sys.exit(1)
