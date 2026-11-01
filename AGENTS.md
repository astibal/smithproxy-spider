# Readability requirements

- Write code, comments and commit messages in English; speak Czech with the user.
- Optimize for a human reading the code slowly, not for compactness.
- Separate validation, preparation, iteration and publication into visual blocks
  with blank lines. Do not run a guard directly into a loop or unrelated work.
- Introduce non-obvious functional blocks with short comments explaining intent
  or invariants. Avoid comments that merely repeat the next statement.
- Prefer explicit intermediate values and ordinary control flow. Avoid dense
  one-liners, nested conditional expressions and unnecessary syntax sugar.
- Keep nesting shallow, but do not fragment a coherent operation into trivial
  helpers just to reduce its length.
- Apply the same readability standards to tests: separate setup, action and
  assertions. Readability-only edits must preserve behavior and be tested.
