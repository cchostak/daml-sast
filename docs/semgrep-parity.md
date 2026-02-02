# Semgrep Solidity parity (targeted subset)

Status legend: ✅ implemented, ➖ not applicable to Daml/LF, ⏳ deferred.

| Area | Semgrep intent (Solidity) | daml-sast rule | Status |
| --- | --- | --- | --- |
| Authorization | Controllers not aligned | DAML-AUTH-001 | ✅ |
| Authorization | Controllers from uncontrolled data | DAML-AUTH-002 | ✅ |
| Authorization | Empty/absent signatories (open access) | DAML-AUTH-003 | ✅ |
| Authorization | Forwarding/exercising without checks | DAML-AUTH-004 | ✅ |
| Keys | Maintainers not subset of signatories | DAML-KEY-001 | ✅ |
| Privacy | Over-broad observers | DAML-PRIV-001 | ✅ |
| Lifecycle | Nonconsuming creates same template | DAML-LIFE-001 | ✅ |
| Lifecycle | Nonconsuming creates any contract | DAML-LIFE-002 | ✅ |
| Determinism | Time-dependent auth/key logic | DAML-DET-001 | ✅ |
| EVM-specific (gas, selfdestruct, delegatecall, inline assembly) | No direct LF analogue | N/A | ➖ |
| Low-level call/tx.origin | No direct LF analogue | N/A | ➖ |

Additions welcome—extend the table when new rules land.
