# Repository Instructions

## Pull request readiness

- Before creating a pull request, marking one ready for review, declaring a branch ready to submit, or completing a PR code review, invoke `$check-pr-conflicts` and run the repository's normal code-review and test workflow.
- Treat an incomplete conflict scan, a direct merge conflict, or an unexplained high-risk overlap as unresolved. Mitigate it or clearly disclose it before submitting the pull request.
- Include the skill's architecture-collision pass even when branches touch different files. Investigate parallel solutions to the same domain capability, favoring domain-driven design and clear hexagonal boundaries where a common architecture is justified.

## Code Review Rules

- Flag active PRs or branches that independently model the same domain capability, lifecycle, state, policy, or extension point. Require an explicit bounded-context and integration decision; a clean textual merge is not sufficient evidence that the designs should remain separate.
