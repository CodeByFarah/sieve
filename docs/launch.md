# Launch drafts

Drafts for announcing Sieve. Every number below is measured and sourced in
[performance.md](performance.md), [ai-evaluation.md](ai-evaluation.md) or the README; nothing is
rounded up. Replace the `[…]` placeholders before publishing, and remove any claim that stops being
true (for example if the demo data is refreshed, the counts change).

Do not publish until the demo is reachable at a public URL. Until then, link the repository only.

---

## 1. Launch post (blog or README-style, ~450 words)

**Sieve: which of your vulnerable dependencies can your code actually reach?**

Point a dependency scanner at an old Flask app and it will list every vulnerable package version it
finds. On the sample app I built for this project, that is 100 findings. Most teams can't triage
100 findings per service, so the list gets ignored, including the entries that matter.

Sieve asks a narrower question: can this application actually reach the vulnerable function? It
reads lockfiles without executing anything, matches pinned versions against OSV (with CISA KEV and
EPSS for exploitation signals), downloads the affected packages from PyPI, and builds a static call
graph across the application and its dependencies. Every finding gets one of three verdicts, and
the evidence behind it.

On that sample app: 9 findings are reachable, each with a call path you can read line by line
(for example, an HTTP route → a config parser → `yaml.load` with `FullLoader`). 43 are not reached.
48 are marked "needs review", and Sieve says why: 32 because nobody has verified which function the
advisory concerns, 16 because the only paths found go through dynamic code.

That last group is deliberate. A wrong "not affected" is worse than an honest "we couldn't tell",
because it can end up in a VEX statement sent to a customer. So the rules are lopsided: dynamic
code can push a finding to "needs review", never to "not reached".

AI is used for one narrow job: proposing which function an advisory is about when nobody has
curated it. The model's answer is untrusted. Every proposed function must exist in the real
package source and be touched by the upstream fix, or it is dropped. On a 32-case golden dataset,
with a deterministic baseline standing in for the model, that verification lifted precision from
17% to 44% and let zero non-existent functions through. I haven't evaluated a live model yet, and
the post will say so until I have.

The rest is what a security team needs around a verdict: human review with an append-only,
hash-chained audit log; OpenVEX and CycloneDX VEX output validated against the official schemas;
pull-request checks driven by a versioned policy; and a threat model in which every mitigation links
to the test that proves it.

A demo scan takes about 10 seconds with a warm cache (29 seconds cold) on a laptop. That's one
small app on one machine, so read it as a description, not a benchmark.

Limitations, stated up front: Python only; static analysis can't see through every dynamic
construct; the golden dataset is small and was labelled during development; nothing is deployed
to AWS yet.

Try the demo: [public URL]. Code and docs: [repository URL].

---

## 2. Short post (LinkedIn / Mastodon / X thread opener, under 280 characters for the first line)

> A scanner reported 100 vulnerabilities in my sample Flask app. 9 were reachable from its code,
> each with the call path to prove it. 43 weren't. 48 Sieve couldn't decide, and it says so.
>
> Built Sieve to show its work: [repository URL]

Optional follow-ups for a thread:

1. AI proposes which function an advisory is about; deterministic checks against the real package
   source decide. In evaluation, 0 non-existent functions got through.
2. "Needs review" is a real answer. A wrong "not affected" is worse than an honest "couldn't tell".
3. Python only, static analysis only, customer code never executed. Limits documented in the README.

---

## 3. Demo script (about 2 minutes, screen recording)

1. **Landing page (10 s).** "A scanner would report 100 vulnerabilities in this sample app. Sieve
   sorts them by whether the code can reach them." Let the dot animation settle into three bins.
2. **Run the live demo (15 s).** Click it; show the scan stages completing in real time. "It never
   runs the app. It reads lockfiles and parses code."
3. **Findings (20 s).** Filter to reachable. Point out the KEV-listed finding and the risk scores.
4. **Evidence page for the PyYAML finding (40 s).** Walk the call path from the HTTP route to
   `yaml.load`, line by line. Show the verified symbols panel and where they came from. Show the
   risk breakdown formula.
5. **A needs-review finding (20 s).** Read its reason aloud. "This is Sieve saying it doesn't know.
   That's intentional."
6. **VEX and activity (15 s).** Open the OpenVEX statement for a reviewed finding; show the
   activity log with "audit log intact".

Avoid on camera: anything about AI accuracy beyond the measured heuristic baseline, any speed claim
other than the measured scan times, and any suggestion that it is deployed or has users.
