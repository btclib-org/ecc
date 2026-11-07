# Repository instructions

Follow [CONTRIBUTING.md](./CONTRIBUTING.md) for issues, pull requests,
local gates, and worktree commands. Use [REVIEWING.md](./REVIEWING.md)
for reviews, [README.md](./README.md) for the package, and
[SECURITY.md](./SECURITY.md) for vulnerability reporting.

Read [REPOSITORY.md](./REPOSITORY.md) before changing workflows, branch
rules, or repository settings.

Keep the primary checkout clean and on `main`; use a separate worktree
for each task, following the setup and cleanup commands in
`CONTRIBUTING.md`.

Read [ASSURANCE_CASE.md](./ASSURANCE_CASE.md) and the *Limitations, not
vulnerabilities* section of [SECURITY.md](./SECURITY.md) before changing
`src/ecc/curves/` or a scheme module in `src/ecc/`: secp256k1 arithmetic
goes to the bindings only where `curves.curve._libsecp256k1_serves`
admits it, so a change there has two paths to keep right.

Choose the least capable model that can reliably complete the task: use
a fast model for straightforward execution, a reasoning-focused model
for multi-step work, and the most capable available model for difficult
or ambiguous problems. Increase capability if progress stalls.
