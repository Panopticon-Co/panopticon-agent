## Summary

<!-- What does this change do, and why? -->

## Changes

<!-- Bullet list of the concrete changes. -->

## Testing

<!-- Commands run and their results, e.g.:
cmake -S . -B build-officer-x64 -G Ninja -DCMAKE_TOOLCHAIN_FILE=... -DVCPKG_TARGET_TRIPLET=x64-windows
cmake --build build-officer-x64
ctest --test-dir build-officer-x64 --output-on-failure
-->

## Security impact

<!--
Does this touch elevation requirements, the response module's
authorization/gating/replay-protection logic, PID-reuse handling, file/path
resolution, or network isolation? If none, say "None."
-->

## Documentation

<!-- README.md, RESPONSE.md, docs/, or other docs updated if behavior changed? -->

## Cross-repository impact

<!--
Does this change the Panopticon event schema (schema/event.schema.json) or
the Manager response command/result contract? If so, list the affected
consumers (panopticon-detection-engine, panopticon-manager,
panopticon-contracts) and whether they were updated alongside this change.
If none, say "None."
-->

## Checklist

- [ ] Tests added or updated for this change
- [ ] Existing tests pass locally (`ctest --output-on-failure`)
- [ ] Documentation updated (README/RESPONSE.md/docs/ as applicable)
- [ ] Security implications considered (see "Security impact" above)
- [ ] Shared contracts updated if this changes the event schema or the
      response command/result contract
- [ ] Cross-repo compatibility checked (detection engine / manager /
      contracts), if applicable
- [ ] No unrelated changes bundled into this PR
