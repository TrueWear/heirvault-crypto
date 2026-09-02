# TrueWear Account Boundary

The organization policy is
[`../../../workspaces/engineering-workspace/ACCOUNT_BOUNDARY.md`](../../../workspaces/engineering-workspace/ACCOUNT_BOUNDARY.md).
Before any commit, push, provider API call, deployment, analytics operation, or
billing operation, run the matching organization preflight and use its
TrueWear wrapper. Never use a provider default or a separately managed company
account. Fail closed when the TrueWear identity and target cannot both be
verified.

<!-- BEGIN:truewear-multi-repo -->

# One checkout, many repos

`~/Documents/TrueWear/repos/heirvault` holds the three independent HeirVault
repositories as siblings. It is not a Git repository and carries no shared
agent instructions. Always run Git commands inside the repository being edited.

Before designing anything, in the repo you are about to change:

```bash
git branch --show-current && git log --oneline -10
```

Read the branch name as a statement of intent and scan recent commits for work
that already solves — or deliberately removes — what you are about to build. A
commit reading "nothing calls these yet; the client and UI follow" means the
design is settled and only the wiring is missing. Doing this after the code is
written is too late.

Cross-repo dependencies are pinned, not linked: `heirvault` consumes
`@heirvault/crypto` as a git dependency pinned to a commit SHA, so edits in the
sibling checkout are invisible until that SHA is bumped and `pnpm install`
reruns.

<!-- END:truewear-multi-repo -->

# heirvault-crypto Agent Instructions

Repo: **heirvault-crypto** (TrueWear, LLC).
