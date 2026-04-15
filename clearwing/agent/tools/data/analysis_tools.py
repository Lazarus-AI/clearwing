"""Agent tools for white-box source code analysis."""

from langchain_core.tools import tool


@tool
def analyze_source(path: str) -> str:
    """Analyze source code at a local path for security vulnerabilities.

    Performs static analysis including pattern matching and AST analysis
    across Python, JavaScript, PHP, Java, Ruby, and Go.

    Args:
        path: Local path to a directory or repository to analyze.

    Returns:
        Analysis summary with all findings.
    """
    try:
        from clearwing.analysis import SourceAnalyzer

        analyzer = SourceAnalyzer(repo_path=path)
        result = analyzer.analyze()
        return result.summary()
    except Exception as e:
        return f"Error analyzing source: {e}"


@tool
def clone_and_analyze(git_url: str, branch: str = "main") -> str:
    """Clone a git repository and analyze it for vulnerabilities.

    Args:
        git_url: Git repository URL to clone.
        branch: Branch to analyze (default: main).

    Returns:
        Analysis summary with all findings.
    """
    try:
        from clearwing.analysis import SourceAnalyzer

        with SourceAnalyzer() as analyzer:
            analyzer.clone(git_url, branch=branch)
            result = analyzer.analyze()
            return str(result.summary())
    except Exception as e:
        return f"Error: {e}"


@tool
def trace_taint_flows(path: str) -> str:
    """Trace data flows from user inputs to dangerous sinks in Python code.

    Performs taint analysis to find paths where user-controlled data
    reaches SQL queries, OS commands, eval(), etc.

    Args:
        path: Local path to Python source directory.

    Returns:
        Summary of discovered taint flows.
    """
    try:
        from clearwing.analysis import TaintTracker

        tracker = TaintTracker()
        tracker.analyze_directory(path)
        return tracker.get_summary()
    except Exception as e:
        return f"Error tracing taint: {e}"
