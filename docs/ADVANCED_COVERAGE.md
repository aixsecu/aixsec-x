# Advanced Coverage (Phase 5)

Every scan can emit `advanced-coverage.json`. It is a coverage contract, not a
vulnerability report, for surfaces that cannot be safely inferred from a
normal URL active scan.

- **Multi-role authorization** reuses isolated `auth_context` sessions,
  `auth_compare` and evidence-bound `authorization_reason`. It becomes ready
  only with at least two authenticated contexts.
- **DOM/browser** coverage is tested only when the AJAX Spider phase actually
  completes. Static JavaScript hints alone are discovery evidence.
- **GraphQL** endpoints are discovered, but active mutation testing requires a
  captured operation or operator-provided schema.
- **SOAP/XML** requires a captured XML request or WSDL before XXE/XML rules can
  receive a valid message.
- **WebSocket** endpoints remain blocked until frames and the WebSocket add-on
  executor are available.
- **OAST** requires both explicit authorization and an operator-controlled
  HTTP(S) callback. `ready` means prerequisites exist, not that a callback was
  observed.
- **Business workflows** reuse declared invariants and observed workflow runs;
  successful HTTP status alone never proves a business-logic flaw.

States are `tested`, `ready`, `discovered`, `blocked`, `not_discovered` and
`unsupported`. Blocked and not-discovered surfaces are coverage gaps, never
evidence that the application is safe.
