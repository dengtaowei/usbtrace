<!-- Title should follow Conventional Commits, e.g. "feat(power): trace autosuspend" -->

## Summary

<!-- What does this change do, and why? -->

## Type of change

<!-- Match your commit type(s). -->

- [ ] feat (new capability / module)
- [ ] fix (bug fix)
- [ ] refactor / perf / style
- [ ] docs
- [ ] build / ci / chore

## Checklist

- [ ] `make` compiles cleanly
- [ ] `./build/usbtrace list` shows the expected modules
- [ ] New/changed module follows `docs/modules.md` and does not edit core
      (`src/main.c`, `src/module.c`, `Makefile`)
- [ ] Docs updated (`docs/`, `README.md`) where relevant
- [ ] Commits follow Conventional Commits (`scripts/check-commits.sh origin/main HEAD`)

## Test notes

<!-- How was this verified? e.g. `sudo ./usbtrace power` output, affected kernel/arch. -->
