# Repository instructions

Follow [CONTRIBUTING.md](./CONTRIBUTING.md) for issues, pull requests,
and local gates. Use [README.md](./README.md) for the
package, and [SECURITY.md](./SECURITY.md) for vulnerability reporting.

Read [REPOSITORY.md](./REPOSITORY.md) before changing workflows, branch
rules, or repository settings.

When an agent works here, a separate worktree per task keeps your own
checkout clean: hooks and agents change files where they run. For
example, `git worktree add ../<name> origin/main -b <branch>`, and
`git worktree remove ../<name>` when done.

Read [ASSURANCE_CASE.md](./ASSURANCE_CASE.md) and the *Limitations, not
vulnerabilities* section of [SECURITY.md](./SECURITY.md) before changing
`src/ecc/curves/` or a scheme module in `src/ecc/`: secp256k1 arithmetic
goes to the bindings only where `curves.curve._libsecp256k1_serves`
admits it, so a change there has two paths to keep right.

Choose the least capable model that can reliably complete the task: use
a fast model for straightforward execution, a reasoning-focused model
for multi-step work, and the most capable available model for difficult
or ambiguous problems. Increase capability if progress stalls.

## Code Review Rules

Review against [REVIEWING.md](./REVIEWING.md). Its *The verdict* says
which review opens with a verdict line and what every other review
posts.

The heading is the one Codex's GitHub review asks for
([Customize what Codex reviews](https://learn.chatgpt.com/docs/third-party/github#customize-what-codex-reviews)).
