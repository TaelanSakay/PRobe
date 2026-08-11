# PRobe

PRobe is a GitHub App that automates security review on pull requests by combining AST-based static analysis, provenance-aware taint tracing, and LLM-adjusted severity scoring.

## Architecture overview

PRobe runs as a small pull-request review pipeline with a backend service, async workers, and a lightweight dashboard.

1. A GitHub pull request webhook arrives at the FastAPI service.
2. The API validates the payload, records the scan in Postgres, and enqueues a Celery task through Redis.
3. The worker parses the PR diff, identifies changed Python files, and builds a diff-aware scan scope.
4. The scanner prunes traversal to the relevant scope and runs AST-based rule matching for common vulnerability patterns: command injection, SQL injection via string formatting, eval injection, and path traversal.
5. For flagged arguments, the provenance layer performs a backward def-use trace to classify whether the value is hardcoded, config-sourced, a function argument, genuine request input, locally computed, or unknown.
6. A Claude-based reviewer adjusts severity using the provenance context and surrounding code, while failing open if the API call fails or returns malformed data.
7. Findings are persisted in Postgres, posted back to the PR as review comments, and surfaced in a React dashboard for scan history and false-positive marking.
8. False-positive feedback is stored as suppression memory and can influence future scans.

A simplified flow looks like this:

```text
GitHub PR webhook
  -> FastAPI validation + enqueue
  -> Celery worker (Redis)
  -> diff parsing
  -> diff-aware scope building
  -> AST rule matching
  -> provenance / taint tracing
  -> Claude-based severity review
  -> Postgres persistence
  -> PR comment + React dashboard
```

## What makes this different from a standard linter or SAST rule set

Most static analyzers flag a dangerous pattern once they see it: `eval(...)`, `subprocess.Popen(..., shell=True)`, or string formatting into SQL. That is useful, but it misses a lot of context.

PRobe adds provenance tracing. Starting from the flagged call, it traces backward through local assignments and helper calls to classify the input according to its origin:

- hardcoded literal
- config-derived value
- function argument
- request or external input
- locally computed value
- unknown

That means severity reflects the actual risk of the sink, not just the presence of a pattern. A hardcoded string passed into `eval()` is treated differently from a value that originated from `request.args.get(...)` and flowed through a helper into the same sink.

## Benchmark results

The provenance layer was evaluated with a self-built benchmark harness under backend/benchmark/ against a labeled corpus of vulnerable and safe code samples, including fixtures designed to exercise one-hop interprocedural resolution.

The current benchmark comparison is:

| Approach | Precision | Recall | False-Positive Rate |
|---|---|---|---|
| Rule-only (pattern match) | 0.64 | 1.0 | 0.50 |
| Provenance-informed | 1.0 | 1.0 | 0.0 |

Building this harness surfaced real issues in the provenance implementation before these values were considered trustworthy. In particular, the initial implementation under-recognized certain request-object access patterns and propagated scope incorrectly in one-hop helper resolution. Those issues were corrected before accepting the reported numbers.

## Provenance tracing technical detail

The provenance layer is implemented as a backward, intra-procedural def-use trace over Python AST nodes. The tracer walks backward from the flagged expression through assignments and helper-return flows to assign an origin category.

### Origin categories

The current implementation distinguishes among:

- `hardcoded`: literal values such as string constants
- `config`: values derived from config/configuration access patterns such as environment lookups
- `function_arg`: values that originate from an enclosing function parameter
- `request_input`: values derived from request-like accessors such as `request.args`, `request.form`, `request.json`, `request.files`, `request.headers`, `request.cookies`, and `request.values`
- `local_computed`: values produced by local computation or by a call boundary that could not be resolved further
- `unknown`: values that could not be traced confidently

### Merge behavior for compound expressions

For compound expressions such as binary operations and f-strings, the tracer computes a worst-case origin across the constituent sub-expressions. A compound expression that mixes a hardcoded literal and request input is treated conservatively according to the most sensitive origin present.

### Safety and termination

The tracer includes two explicit safeguards:

- cycle detection, so recursive or self-referential local assignments terminate cleanly
- maximum-depth guarding, so pathological traces do not recurse indefinitely

### Bounded interprocedural tracing

The implementation deliberately bounds interprocedural tracing to one hop. A local helper call is resolved by binding callee parameters to the call-site arguments and tracing the helper return expression, but the tracer does not attempt full call-graph-based interprocedural analysis.

This is an explicit design decision for the current version. Full interprocedural analysis would require building a call graph and running a fixed-point analysis to handle recursion, cycles, and mutually recursive helper chains safely. A one-hop boundary is simpler, easier to reason about, and sufficient for the initial version of the system.

## Diff-aware scanning

PRobe does not scan every file in a repository on every PR. Instead, it uses the PR diff to identify modified Python files and the changed line numbers, then expands the scan scope to the enclosing function and one-hop same-file callers. This keeps the AST traversal focused on the code most likely to matter for the review and reduces noise from unrelated parts of the repository.

## Current status and limitations

The core scanning and provenance pipeline is implemented and covered by unit tests. The Claude-based reviewer is also implemented: it builds prompts per file, batches findings, parses responses, merges severity adjustments back into the finding objects, and fails open if the API request fails, times out, or returns malformed content.

That said, there are important limitations:

- The Claude severity review path is implemented and unit-tested against mocked API responses, but it has not yet been verified against the live Anthropic API.
- One-hop helper resolution uses simple name matching and does not yet resolve cases such as `self.method()` or cross-module calls.
- Live deployment is not yet set up.

These limitations are documented explicitly because they are part of the current engineering boundary, not a claim of broader maturity than the implementation supports.

## Tech stack

- FastAPI for the webhook and API layer
- Celery for asynchronous PR scan execution
- Redis as the Celery broker
- PostgreSQL for scan and finding persistence
- React for the dashboard UI
- Python `ast` module for static analysis
- Anthropic API for severity review
- Docker for local orchestration

## Local setup

The repository includes a Docker Compose configuration for the core services.

1. Create a `.env` file at the repository root with the environment variables required by the backend, including GitHub App configuration and any Anthropic settings needed for the reviewer path.
2. From the repository root, start the services:

```bash
docker compose up --build
```

This starts:

- the Postgres database
- the Redis broker
- the FastAPI web service on port `8000`
- the Celery worker

### Running tests

The backend test suite is run with `pytest`.

Examples:

```bash
cd backend
py -3 -m pytest -q tests/test_provenance.py
py -3 -m pytest -q tests/test_benchmark.py
py -3 benchmark/run_benchmark.py
```

For the frontend dashboard, the Vite app can be started from the frontend directory with:

```bash
cd frontend
npm install
npm run dev
```
