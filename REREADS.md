# Sourcehunt reread investigation

> This document describes the behavior observed in the September 28 runs.
> The read-path changes below were made afterward; the trace evidence and
> historical code analysis remain as recorded.

## Read-path fix status

The deep `read_file` default is now 100 lines. The hunter sends complete source
lines up to a 12,000-character target, reports the file's total lines and an
explicit next line, and sets EOF only when the delivered content reaches the
file end. Tool-start events use the same requested range as the handler.
The handler's existing 100,000-character raw output cap still applies to
exceptionally long source lines.

The run-wide coverage ledger, policy for deliberate rereads, and resolved-lead
memory are separate follow-up areas. The September 28 traces predate the
read-path changes, so they do not measure their effect.

## TL;DR

The strongest reread causes are:

- `read_file` accepts a default 2,000-line window, but the hunter sends only 3,000 characters of that result to the model. Large requests therefore become implicit pagination work.
- The response says `EOF: True` when the **requested** range reaches the file end, even when the model received only a clipped prefix. That makes the range metadata contradictory.
- The durable read ledger used by the stall guard is internal. The model does not receive `deep_read_ranges`, and the model-facing `visible_read_ranges` ledger is cleared after context compaction.
- Overlapping reads are not blocked. The duplicate-call guard catches repeated identical calls, while different overlapping ranges remain valid tool calls.
- Pagination and recovery reads consume ordinary model steps, tokens, cost, and time. The runtime does not distinguish necessary recovery from redundant rereading.
- The tool schema advertises a 2,000-line default while the hunt guidance recommends 40–120-line windows. The schema makes broad first reads the natural behavior.
- Long hunts lose detailed reasoning during context summarization. There is no durable model-visible ledger for inspected ranges or resolved leads, so the model can reopen hypotheses and reread code it previously resolved.

The September 28 traces support two distinct behaviors. Many apparent overlaps were legitimate pagination after the 3,000-character clip. The OpenSSL trace also shows genuine non-convergent rereading: after dismissing its main lead, it made seven consecutive reads that returned no new lines. The jq trace ended with a model-service request failure; gitoxide spent most of its late runtime waiting for compilation; html-sanitizer spent its late runtime trying to obtain PHP.

## Evidence from the September 28 traces

Counts below use the line ranges actually shown to the model in trajectory `tool_result` summaries, not the larger ranges requested by the model.

| Hunt | `read_file` calls | Calls with repeated shown lines | Fully redundant calls | Repeated shown lines |
|---|---:|---:|---:|---:|
| OpenSSL (`sh-6a1007b0`) | 46 | 11 | 10 | 465 |
| jq (`sh-20215022`) | 50 | 4 | 2 | 167 |
| gitoxide (`sh-1f3e2641`) | 27 | 3 | 1 | 8 |
| html-sanitizer (`sh-f5011a27`) | 17 | 3 | 0 | 8 |

OpenSSL is the clearest stall example. Steps 53–59 returned no new lines after the model dismissed its OCB tag hypothesis at step 52. The model then stopped with `stop_reason=stalled` at step 60. Its reasoning repeatedly said to re-read or reconsider already examined nonce, stream, table, and tag logic.

The other traces show why requested-range overlap is not enough to diagnose the problem. For example, a request for lines 1–2000 can expose only lines 1–98 to the model. The next request beginning at line 98 overlaps the requested interval but is necessary to retrieve content that was never visible.

## 1. Response clipping turns one read into multiple model steps

The deep-agent `read_file` handler executes `awk` over the requested range:

- `clearwing/agent/tools/hunt/deep_agent.py:300-338`

The handler's local output cap is 100,000 characters (`deep_agent.py:41`, `deep_agent.py:109-114`). The sourcehunt loop then applies a stricter cap before constructing the model-facing result:

- `clearwing/sourcehunt/hunter.py:2687-2724`
- `hunter.py:2698` calls `_clip_text(content, 3000)`.

The model therefore may request 2,000 lines but receive only the first few thousand characters. The `Returned` range is calculated from the clipped text (`hunter.py:2699-2704`), so `Returned: 1-98` accurately describes what the model saw in that response.

This creates extra model turns for large files. Those turns are ordinary investigation steps and consume context, tokens, cost, and wall-clock time even when they only retrieve the rest of a previously requested window.

## 2. `EOF` describes the request, not the delivered response

The response metadata computes EOF from the requested range:

- `clearwing/sourcehunt/hunter.py:2707`

```python
eof = total_lines is not None and requested[1] >= total_lines
```

It does not use the last line actually delivered. This permits a contradictory response such as:

```text
Requested: 1-2000
Returned: 1-98
EOF: True
Truncated: True
```

The model can reasonably interpret `EOF: True` as saying that there is no more source to retrieve, while `Truncated: True` says that the response was clipped. This ambiguity encourages repeated probing and makes the model's next offset choice less reliable.

## 3. The initial default is much larger than the model-visible window

The tool schema exposes these defaults:

- `clearwing/agent/tools/hunt/deep_agent.py:49-67`
- `deep_agent.py:511-520`

```python
offset = 0
limit = 2000
```

When the model calls `read_file` with only a path, it is not reporting that it knows the file has 2,000 lines. It is accepting the tool's default maximum window. It generally does not know the total line count unless it first runs a command such as `wc -l`.

The older hunt rules recommend tight 40–120-line windows (`clearwing/sourcehunt/hunter.py:400-412`), but the deep-agent schema advertises 2,000 lines. This contract mismatch makes broad first reads likely and guarantees more clipping on long files.

## 4. The model never receives the durable `deep_read_ranges` ledger

The stall loop keeps a durable per-run map called `deep_read_ranges`:

- initialization: `clearwing/sourcehunt/hunter.py:1636-1637`
- update: `hunter.py:2183-2197`

The map is used internally to decide whether a returned range contains any lines not previously returned. It is not serialized into a prompt, situation report, or tool schema. The model cannot directly see a statement such as:

```text
You already inspected src/foo.c lines 200-300.
```

The model may remember earlier tool output while it remains in context, but it has no authoritative run-wide coverage map to consult. The tool also does not reject a new overlapping range.

## 5. Context compaction resets the model-facing coverage map

The hunter maintains a second map, `visible_read_ranges`, for calculating the `Overlap` and `New lines` fields shown to the model:

- initialization: `clearwing/sourcehunt/hunter.py:1606-1613`
- use when formatting a read: `hunter.py:2183-2189`
- update: `hunter.py:2195-2197`

When the conversation is summarized, the code clears this map:

- `clearwing/sourcehunt/hunter.py:1829-1833`

```python
messages = await self.summarizer.summarize(messages, self.llm)
visible_read_ranges.clear()
```

The summarizer activates when estimated message size exceeds 80% of 150,000 tokens, approximately 120,000 estimated tokens:

- `clearwing/data/memory/summarizer.py:23-40`

The durable `deep_read_ranges` map is not cleared, so the progress guard can still know that a range was seen. The model-facing overlap metadata, however, starts a new epoch. A reread after compaction can therefore be reported as having no overlap even though the same lines were shown earlier in the run.

The summarizer preserves some old tool messages, but it does not provide a durable, explicit source-coverage ledger or resolved-lead ledger in the model prompt. That leaves the model dependent on imperfect memory and attention over the remaining conversation.

## 6. The duplicate-call guard does not block overlapping ranges

The runtime counts repeated tool calls by a key based on tool name and serialized arguments:

- `clearwing/sourcehunt/hunter.py:2020-2070`

For `read_file`, arguments are deliberately kept literal because offsets and limits are legitimate pagination parameters. As a result, calls such as these are different calls:

```text
read_file(... offset=213, limit=50)   # lines 214-263
read_file(... offset=213, limit=30)   # lines 214-243
```

The exact-call skip mechanism does not identify the second call as a subset of the first. The range-aware progress check notices that it adds no new lines, but only after the model has spent the step.

## 7. Necessary pagination and redundant rereads share the same budget

The stall guard treats a read as progress only when its returned range contains previously unseen lines:

- `clearwing/sourcehunt/hunter.py:1621-1628`
- `hunter.py:2190-2194`
- `_uncovered_read_ranges`: `hunter.py:2655-2675`

If a clipped response is followed by a continuation containing new lines, the continuation resets the no-progress counter. If a response contains only old lines, it does not. In both cases, however, the model step and token/cost accounting already apply.

There is no separate budget for source pagination, no refund for a required continuation, and no distinction between:

- recovering content omitted by the response cap;
- a small boundary overlap;
- deliberate revalidation; and
- a completely redundant reread.

This makes a large file or a long context more likely to hit time, token, or step limits before the investigation reaches synthesis.

## 8. Resolved leads are not durable enough to prevent hypothesis churn

The OpenSSL trace provides direct evidence of a behavioral loop independent of pagination. The model:

1. formed a plausible OCB tag hypothesis;
2. investigated and dismissed it at step 52;
3. immediately reread already covered OCB ranges at steps 53–59;
4. continued reconsidering related nonce, stream, and table logic;
5. stopped as `stalled` without a finding.

The runtime tracks potential objects and findings, but it does not inject a concise, durable record saying that a lead was resolved and which evidence resolved it. Context summarization can further weaken the model's memory of the reasoning. The same pattern appeared in jq around speculative string-allocation overflow checks, although jq ultimately failed on a model-service request rather than the stall guard.

## 9. Range bookkeeping has inconsistent defaults

The tool schema and handler use a 2,000-line default (`deep_agent.py:56-58`, `deep_agent.py:300-303`), while `_run_tool` uses a 500-line fallback when emitting tool-start events:

- `clearwing/sourcehunt/hunter.py:2503-2508`

This does not change the handler's actual read result when the model omits `limit`, but it can make event logs and diagnostics report a different requested end line from the tool that actually ran. That inconsistency complicates reread analysis and can hide how large the model's implicit request was.

## 10. Observability hides the reasoning needed to separate the causes

The original Phoenix report script stores model step text and tool calls but does not include `reasoning_content` or hunter span error messages. That made the first pass look like many broad overlapping reads and hid:

- that most reads were clipped pagination;
- that OpenSSL explicitly re-read after dismissing a lead; and
- that jq's hunter ended with a LiteLLM request error while the root run was marked completed.

The original trajectories contain the model-visible `Returned`, `Overlap`, and `New lines` headers and are required for accurate reread counts. Any future report should preserve those fields, the hunter `statusMessage`, and model reasoning or a structured explanation of why a read was repeated.

## References

- Hunter implementation: `clearwing/sourcehunt/hunter.py`
- Deep-agent tools: `clearwing/agent/tools/hunt/deep_agent.py`
- Context summarization: `clearwing/data/memory/summarizer.py`
- September 28 normalized report: `/tmp/sourcehunts_sep28_2026.json`
- September 28 reasoning export: `/tmp/sourcehunts_sep28_reasoning.json`
- Original trajectory records: Phoenix run artifacts under `cvehunt-runs/20260928T182839/artifacts/.../results/sourcehunt/`
