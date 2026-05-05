# AGENTS.md

## Current goal
Integrate an embedded LLM analyst into SentinelIoT without destabilizing the current product.

## Priorities
1. Preserve current working scan/monitor/risk/dashboard flows
2. Add backend-first LLM integration
3. Keep changes incremental and reviewable
4. Prefer grounded answers from project data over generic LLM responses
5. Test with real project data before polishing

## Do not do
- no broad architecture rewrite
- no database migration
- no auth/JWT work
- no PDF export work
- no unrelated UI redesign
- no speculative features outside the requested task

## Expected workflow
- inspect first
- produce a short file-level plan
- then implement
- keep diffs scoped
- summarize changes and remaining risks

## LLM rules
- LLM must run through backend services, not directly from frontend
- Answers must be grounded in system data
- If context is missing, the assistant should say it clearly
- Prefer concise operational answers over generic security essays

## Definition of done
A task is done only if:
- the feature works with current project flows
- build still passes
- touched code paths remain understandable
- error/loading states are handled reasonably