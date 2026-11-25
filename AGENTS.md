# Notes for coding agents

- The job of a coding agent is to automate ticket work and gather information.
  Do not autonomously give tasks to humans, get blocked by posting questions or
  derail conversations with reams of text unless it's useful and relevant. Speak
  to your operator if you have blocking questions, open issues for follow up
  work and bugs.
- Don't add to the `README.md`s or `docs/` or they'll become out of date slop
  bombs. Let the maintainers write those. API detail belongs next to the API:
  rustdoc, the JSDoc in `npm-src/*.d.ts`, or `rars.pyi`. Measurements, caveats
  and findings go in the PR description or the issue.
- Comments describe surprising things about the code, they are not a dev diary
  or a place to state the obvious. Don't write history these ("used to",
  "previously", "before #N"), or information that changes and goes stale; that
  belongs in the commit message or PR.
- Clean room: never read or copy UnRAR's source, or 7-Zip's `Rar*` code. Learn
  behaviour by running the tools and from bitplane/rar-research when needed.
- `unsafe` goes only in `crates/rars/src/simd.rs`; a test enforces it.
- Parallel work uses rayon, not a hand-rolled thread pool or queue.
  Output must be byte-identical at any thread count: pin new parallel
  paths with a test at 1, 2 and many threads.
