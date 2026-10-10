# Policy regression corpus

Every file here (kept outside policies/ so OPA does not load it as data) is a recorded policy input with the decision it must produce.
`make policy-test` replays all of them against the current policies; a change
that flips any expected decision fails CI. Add a case whenever production
produces a decision worth protecting (an incident, a customer-visible deny, a
new rule's canonical example).

Shape: `{"name", "rule", "input", "expect": {"allow", "deny_reason_contains"?, "obligations"?}}`
