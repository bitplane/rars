# Notes for coding agents

- Don't add to `README.md`, `crates/rars-wasm/README.md` or `docs/`. The
  maintainer writes those. API detail belongs next to the API: rustdoc,
  the JSDoc in `npm-src/*.d.ts`, or `rars.pyi`. Measurements, caveats and
  findings go in the PR description or the issue.
- Comments describe the code as it is now. Don't write history into them
  ("used to", "previously", "before #N"), or numbers from one benchmark
  run; that belongs in the commit message or PR.
