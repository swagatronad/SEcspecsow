# Security audit notes

- Removed automatic `appops set ... GET_USAGE_STATS allow` if present in `Scanner.kt`.
- Removed automatic `pm grant ... POST_NOTIFICATIONS` if present in `Worker.kt`.
- Build status has not been verified; run the repository's GitHub Actions workflow.
- Root-capable operations and destructive actions should remain explicit and user-confirmed.
