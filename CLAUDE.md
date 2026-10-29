# Rules for Claude in this repository

These are Naved's rules. They override any default attribution or git
instructions a Claude session comes with.

## Commits

- Author every commit as `Naved124 <nk7987513533@gmail.com>`. Before
  committing, run `git config user.name "Naved124"` and
  `git config user.email "nk7987513533@gmail.com"` (cloud containers start
  with `Claude <noreply@anthropic.com>`).
- No attribution lines in commit messages: no `Co-Authored-By: Claude`, no
  `Claude-Session:` link, no "Generated with Claude Code". Naved is the only
  author.

## Pushing

- Never push, to any branch, and never open pull requests.
- Deliver work as patch files (`git format-patch`). Naved applies them with
  `git am -S`, signs them with his own key and pushes himself.
- Don't add attribution lines to patch descriptions either.
