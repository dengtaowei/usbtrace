# Contributing to usbtrace

Thanks for helping improve usbtrace. This document covers the build/test loop,
the commit-message convention, and what CI enforces before a PR can merge.

## Build & test locally

```bash
make deps                 # one-time: host toolchain + git submodules
make                      # -> build/usbtrace (+ ./usbtrace symlink)
./build/usbtrace list     # smoke test: module registry (no root needed)
sudo ./usbtrace urb       # run a module (needs root + kernel BTF)
```

Before opening a PR, run the same checks CI runs:

```bash
make                                   # must compile
./build/usbtrace list                  # must list modules
shellcheck scripts/*.sh                # shell lint
scripts/check-commits.sh origin/main HEAD   # commit-message lint
```

## Commit messages: Conventional Commits

Every commit subject MUST follow
[Conventional Commits](https://www.conventionalcommits.org/):

```
<type>(<scope>)!: <description>
```

- **type** (required), one of:
  `feat` `fix` `perf` `refactor` `docs` `build` `ci` `test` `chore` `style` `revert`
- **scope** (optional, recommended): usually the module or area touched —
  `urb` `enum` `lifecycle` `power` `cli` `core` `build` `ci` `docs` `deps`.
  Multiple scopes may be comma-separated.
- **!** (optional): marks a breaking change.
- **description**: imperative mood, lower-case start, no trailing period.
- Subject length: **<= 72 characters**.

Examples:

```
feat(power): trace autosuspend/autoresume
fix(urb): correct giveback status read
docs(modules): document --json output
ci: add native build gate
refactor(cli)!: rename usbtrace_filter fields
```

`Merge ...` and `Revert ...` auto-subjects are exempt. The rule is checked by
[`scripts/check-commits.sh`](scripts/check-commits.sh) and enforced in CI on the
commits a PR introduces.

## Coding style

usbtrace follows Linux-kernel C conventions:

- SPDX header on every source file; BPF programs are GPL
  (`char LICENSE[] SEC("license") = "GPL";`).
- Tabs for indentation.
- In BPF code, read kernel fields only via `BPF_CORE_READ(...)` — never hardcode
  offsets (CO-RE keeps one source portable across kernels and arches).
- New capabilities are self-contained modules under `src/modules/<name>/`
  (`<name>.bpf.c` + `<name>.c` + `<name>.h`). Adding a module must NOT require
  editing `src/main.c`, `src/module.c`, or the `Makefile`. See
  [docs/modules.md](docs/modules.md).
- Reuse shared helpers: `usbtrace/cli.h` (user space) and
  `usbtrace/filter.bpf.h` (BPF) instead of duplicating filter/format logic.

## Pull-request flow

1. Branch off `main`.
2. Make changes; keep commits focused and well-described (see above).
3. Ensure `make` builds and `./build/usbtrace list` works.
4. Open a PR against `main` and fill in the template.
5. CI must be green before merge:
   - **build (native x86_64)** — required gate; the project must compile and the
     binary must list its modules.
   - **shellcheck** — shell scripts lint clean.
   - **commit messages** — commits follow Conventional Commits.

## Cross-compilation (local, not yet in CI)

The build supports `x86 / x86_64 / arm / arm64`. Cross-compiling the BPF objects
needs a target-arch `vmlinux.h` (the kprobe `PT_REGS_*` macros reference
arch-specific types such as `struct user_pt_regs`), so provide the target BTF:

```bash
make ARCH=arm64 CROSS_COMPILE=aarch64-linux-gnu- VMLINUX_BTF=/path/to/arm64/vmlinux
```

See [docs/build.md](docs/build.md). Cross builds are not yet gated in CI; they
will be added once a per-arch BTF source is wired up.
