<!-- BEGIN:truewear-multi-repo -->

# One checkout, many repos

`~/Documents/TrueWear` holds several independent git repos (`heirvault`,
`heirvault-admin`, `heirvault-crypto`, `stackdeck`, `truewear`, `ziplet`) inside
one parent repo. Tooling that reports "the" branch often reports the
**parent's**, which says nothing about the repo you are editing.

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
