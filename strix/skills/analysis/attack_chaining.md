---
name: attack_chaining
description: How to chain confirmed findings into end-to-end attack paths — what counts as a chain, how to test it, and how to report one that turns out not to combine
---

# Attack Chaining

Two confirmed findings are often worth far more together than either is
alone. An SSRF that reaches only internal metadata is a medium. An SSRF
plus a permissive internal service is a full compromise. The gap between
those two reports is the whole value of this skill.

Chaining is not optional polish. It is the step where you find out what
the customer actually has to lose.

## What Counts as a Chain

A chain is a **demonstrated** sequence where the output or side effect of
one finding becomes the input that makes another exploitable or more
severe. Both ends must be real:

- Link 1 must be confirmed, not suspected.
- The join must be tested — you pass real data from one into the other.
- The final impact must be shown, or clearly bounded with evidence, not
  asserted.

If you cannot test the join, you do not have a chain. You have two
findings and a hypothesis. Report them as two findings and record the
hypothesis as a `needs_follow_up` surface — never as a confirmed chain.

## Chaining Candidates Worth Trying

Work through these deliberately rather than waiting for an idea to strike:

**Information → access.** A disclosure finding (verbose error, exposed
config, leaked token, directory listing) feeding an authentication or
authorization bypass.

**Read → write.** A read-only primitive (LFI, SQLi read, arbitrary file
read) escalating into code execution or data modification.

**Low-privilege → high-privilege.** An IDOR or role-confusion finding
combined with an administrative endpoint that trusts the same weak check.

**Server-side → internal network.** SSRF, XXE, or command execution used
to reach a service that is not exposed externally — then that service's
own weakness.

**Dependency CVE → application reachability.** A vulnerable library the
application actually calls with attacker-influenced input. Reachability
is the whole question: an unreachable CVE is not a chain.

**Client-side → server-side.** A stored XSS or prototype-pollution
finding used to forge a privileged request from an operator's session.

## Testing the Join

The join is where chains fail and where reports go wrong. Be concrete:

1. Take the **actual output** of link 1 — the leaked token, the file
   contents, the internal response — and feed it into link 2.
2. Capture the whole exchange: what came out of link 1, what you sent
   into link 2, what came back.
3. Use a marker string unique to this test so the evidence is
   unambiguous. "The response was 200" proves nothing; "the response
   contained `CHAIN-MARKER-<random>` that only exists inside the file I
   read via LFI" proves the join.
4. Run `verify_poc` on the full chain, not on the links separately. A
   chain that works only when you type the two halves by hand has not
   been demonstrated.

## When a Chain Does Not Combine

Finding that two findings are independent is a real result — say so, and
say why. A reasoned negative is worth more to the customer than a
speculative chain, because it tells them where the boundary actually is.

Record a non-combining pair explicitly rather than dropping it: it stops
the next reviewer from re-trying the same combination from scratch.

## Reporting a Chain

File the chain as its own vulnerability report, with:

- `title` naming the end-to-end outcome, not the individual links.
- `poc_script_code` running the whole sequence.
- `technical_analysis` walking each hop and what it contributed.
- `impact` describing the final position, not the sum of the parts.

Keep each link's standalone report as well when it is independently
fixable — the customer may patch one hop before the other, and they need
to see what remains after each fix.
