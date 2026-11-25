# Notes for coding agents

- Don't add to `README.md`, `crates/rars-wasm/README.md` or `docs/`. The
  maintainer writes those. API detail belongs next to the API: rustdoc,
  the JSDoc in `npm-src/*.d.ts`, or `rars.pyi`. Measurements, caveats and
  findings go in the PR description or the issue.
- Comments describe the code as it is now. Don't write history into them
  ("used to", "previously", "before #N"), or numbers from one benchmark
  run; that belongs in the commit message or PR.
- Clean room: never read or copy UnRAR's source, or 7-Zip's `Rar*` code
  (it derives from UnRAR). Learn behaviour by running the tools and from
  bitplane/rar-research. Test fixtures are synthetic.
- `unsafe` goes only in `crates/rars/src/simd.rs`; a test enforces it.
- Parallel work uses rayon, never a hand-rolled thread pool or queue.
  Output must be byte-identical at any thread count: pin new parallel
  paths with a test at 1, 2 and many threads.
