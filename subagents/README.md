# Review Subagents

This folder contains reusable specialist briefs for reviewing and improving the `ms-defender` project.

Use these subagents when you want a structured multi-pass review instead of a single general-purpose audit. Each subagent has a narrow job, a preferred evidence source, and a defined output format so findings are easier to compare over time.

For unattended or low-touch maintenance, use `orchestrator-subagent.md` to run only the checks that do not require UAC or interactive approval.

## Recommended Order

1. `latest-info-subagent.md`
2. `audit-subagent.md`
3. `document-subagent.md`
4. `test-subagent.md`
5. `idea-subagent.md`

## Hourly No-UAC Loop

Use `orchestrator-subagent.md` when you want an hourly unattended pass. It should:

- avoid live Defender recordings and any UAC-triggering path
- run parser, module import, fixture, compare, and safe synthetic workload checks
- review repo drift and subagent docs
- consolidate findings into one status summary for the next interactive session

## Expected Outcomes

- `latest-info` validates current Microsoft Defender guidance and flags repo logic that may be stale.
- `audit` reviews code quality, correctness, safety, and recommendation logic.
- `document` checks README/help/examples against the code as it exists today.
- `test` validates module import, fixtures, compare mode, and live or synthetic checks where safe.
- `idea` proposes worthwhile new capabilities based on the repo, current guidance, and observed gaps.

## Good Review Hygiene

- Prefer official Microsoft documentation for product behavior and syntax.
- Use Cloudbrothers as practical guidance, not the sole source of truth.
- Treat exclusion recommendations as last-resort performance fixes.
- Prefer narrower recommendations over broader ones.
- Distinguish production evidence from synthetic validation evidence.
- Call out when "no exclusion" is the correct answer.

## Suggested Consolidation Format

After running all subagents, combine them into one summary with:

1. Critical or high-risk fixes
2. Documentation updates
3. Test gaps
4. Fresh guidance changes
5. Next-version ideas
