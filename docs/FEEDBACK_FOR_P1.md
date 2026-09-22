# Feedback for P1 -- from real scan test (Week 5-6)

Ran your `scan_output.json` (scan-91bb53f1-a656-41ca-8132-48ad4c8ac9c3) through
the full P2 pipeline. Good news first: **all 8 findings validated cleanly
against both schemas, and the enrichment pipeline produced correct scores
and explanations with zero errors and zero gaps reported.** The rewrite
holds up on real data, not just the synthetic test I ran earlier.

One real issue found, worth fixing before the review demo:

## `SG_OPEN_TO_WORLD` -- `exposed_ports` comes back empty

Both `demo-open-sg-576c93` and `cspm-open-test` fired correctly, but
`context.exposed_ports` was `[]` for both, even though the demo task asked
for a specific port (22 or 3306) to be opened. Looking at your `sg_rules.py`
logic: `exposed_ports` only gets populated when `FromPort`/`ToPort` are both
present in the AWS response. AWS omits these fields entirely for
"all traffic" rules (protocol `-1`) -- so if either security group was
created allowing all traffic rather than a specific port, that's why the
list came back empty.

**Effect on scoring:** these two findings scored 40 instead of what a
correctly-identified port would have scored (P2's `sensitive_port` factor,
worth 25 points, needs a port in `exposed_ports` to fire). A fully-open
security group is arguably worse than a single-port exposure, but right
now it scores the same as one, purely because of this data gap -- not
because the underlying misconfiguration is actually less severe.

**Two ways to fix, your call:**
1. If the demo SGs were created as "all traffic" rules, change them to open
   a specific port instead (22 or 3306, as originally planned) -- simplest
   fix, no code change needed.
2. If you want the rule to handle "all traffic" correctly going forward
   (not just for this demo), have `sg_rules.py` populate `exposed_ports`
   with the full list of known-sensitive ports whenever the permission's
   protocol is `-1` / covers all ports, since an all-traffic rule
   technically does expose every one of them.

Either is fine for the demo -- just flagging it now so it's not a surprise
on review day. Full detail (including the other 4 already-resolved
contract items) is in `docs/P2_DECISIONS_LOG.md` if useful.
