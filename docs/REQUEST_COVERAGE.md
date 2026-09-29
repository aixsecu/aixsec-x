# Request Coverage and Safe Seeds

Discovery now produces an input-level `request-coverage.json` before route
families or technology prioritization are applied. HTML forms, JavaScript
endpoints and captured traffic share one request-template identity based on
origin, method, path, input names/locations and authentication context.

Uncaptured GET templates receive harmless `aixsec-test` values and enter the
active schedule before family reduction. The complete HAR-shaped request is
imported into ZAP, allowing every installed/allowed active rule to operate on
the parameterized request rather than a URL-only node. Synthetic imports are
not treated as proof of a target response: only the active observer can move a
template to `active_tested`.

Sensitive inputs (tokens, passwords, CAPTCHA, sessions and API keys) are not
seeded. A dynamic token makes an uncaptured form `blocked_by_csrf`; the scanner
requires a fresh captured request instead of inventing a credential. POST
search/filter forms without sensitive or destructive fields receive a bounded
form-urlencoded seed. Other uncaptured writes remain `skipped_by_policy` rather
than being submitted blindly. Captured POST/PUT/PATCH requests continue through
the existing scheduler with their original body and authentication context.

The report separates discovery readiness from active evidence:

- `seeded`: a safe request is ready for ZAP import.
- `requested` / `tested`: baseline traffic already contained the request.
- `active_tested`: active requests were attributed by the observer.
- `active_attempted`: the job ran but request evidence was incomplete.
- `skipped_by_policy`: intentionally not sent, with a reason.
- `unaccounted_inputs`: an implementation gap; discovery is partial.

Route-family optimization runs only after this inventory and seed admission
step, so optimization cannot silently remove an otherwise unknown input.
If the coverage gate is not ready, family reduction is skipped. Technology
capability analysis defaults to `priority`: unlikely rules are deferred but not
removed. Only the explicit `strict` mode may reduce the allowed rule set.
