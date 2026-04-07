# Policy regarding LLM-generated contributions to Vulnera

## Foreword

Vulnera accepts contributions prepared with LLM-based tooling Partially. The purpose of this policy is to require disclosure of such use while preserving code quality, maintainability, security, and reviewer efficiency.

## Hard requirements

The following rules are mandatory for any contribution that uses LLM-based tooling in any substantial way.

- The contributor is responsible for every line of code, comment, documentation line, test, and design decision in the contribution, regardless of whether it was written manually or generated with assistance.
- The pull request description must match the actual contents of the contribution.
- If the contribution claims to address a tracked issue, it must satisfy the requirements of that issue as discussed in the issue thread.
- The contributor must be able to explain the solution in detail and answer reviewer questions without deferring understanding to an LLM.
- The contributor must test the change locally before submitting it for review.
- The contribution must compile successfully and must not regress the repository's automated checks.
- Contributions should include automated tests whenever feasible. If automated tests are not feasible, the pull request description must explain why and describe the manual validation performed.
- Contributions involving security-sensitive areas, including authentication, authorization, sandboxing, SQL, cryptography, secrets handling, or network boundaries, require extra care and explicit human review.

## Disclosure requirement

If you used LLM-based tooling at any point while preparing a contribution, you must disclose that fact in the pull request description.

The disclosure should state:
- whether LLM-based tooling was used
- the approximate extent of use, such as `not at all`, `minimally`, `moderately`, or `extensively`
- the parts of the contribution that were assisted, if relevant

A short example disclosure:

- `LLM usage: moderately, used for drafting the initial patch and test outline; all code reviewed, edited, and validated locally by me.`

## Hook-based reminder

This policy is intended to be reinforced by the repository's `.githooks/pre-commit` hook.

Recommended hook behavior:
- Remind the contributor that if LLM-based tooling was used, the pull request description must include a disclosure.
- Encourage the contributor to verify that tests were run locally before submission.
- Keep the reminder advisory and non-blocking.

Example reminder:
- `pre-commit: If this change was prepared with LLM assistance, ensure the PR description includes an LLM usage disclosure.`

## Enforcement

Maintainers may reject or request revision of contributions that do not comply with this policy.

This policy is intended to support high-quality contributions, not to discourage AI-assisted work when used responsibly.
