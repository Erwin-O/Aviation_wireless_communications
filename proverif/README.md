# ProVerif models

> **Authorship.** The three models in this directory are the work of
> Frederic Lafitte. They are included here with his permission. They are
> formal models, not part of the implementation, and nothing in the
> implementation depends on them. The rest of this repository is Erwin Orye's
> work. See `../NOTICE`.

Formal models of the protocol's security goals in the symbolic (Dolev–Yao)
model, where the network is entirely under adversarial control and the
cryptography is treated as perfect. A result here is therefore a statement
about the protocol's logic, not about the strength of its primitives.

| File | Establishes |
|---|---|
| `model_aka.pv` | G1 aircraft authentication, G2 ground-station authentication, G6 KCI resistance, G7 explicit key confirmation |
| `model_keys.pv` | G3 session-key secrecy, G4 session-key independence, G5 perfect forward secrecy |
| `model_cmd.pv` | G10 replay resistance, G11 in-order command execution |

## Running them

```bash
proverif model_aka.pv
proverif model_keys.pv
proverif model_cmd.pv
```

ProVerif is available from <https://bblanche.gitlabpages.inria.fr/proverif/>.
The expected outcome of each query is stated in the comments at the head of
each file.

## What they are and are not

The three models are **not composed**. Each abstracts whatever is not
material to the property it carries, so a result from one does not
automatically transfer to another:

- `model_aka.pv` has an unbounded number of sessions and allows participants
  to be corrupted; it says nothing about key secrecy over time.
- `model_keys.pv` uses ProVerif's phases to separate what an adversary learns
  before, during and after a session, which is how forward secrecy is
  expressed; it takes authentication as given.
- `model_cmd.pv` fixes two sessions and four commands and takes the session
  keys as given, so its results on replay and ordering hold for a bounded
  scenario rather than for unboundedly many.

In `model_cmd.pv` the participants named `G1` and `G2` are ground stations.
They are unrelated to the goal labels `G1` and `G2` above.

Four of the thirteen goals are not established here, because they lie outside
what a symbolic model represents: G8 unknown key-share resistance, G9
resilience to weak randomness, G12 authorisation, which includes the airspace
a ground station claims, and G13 exclusive ground-station control. They are
discharged by argument instead, in the paper cited in `../CITATION.cff`.

## History

Earlier, exploratory models — a six-phase decomposition written in June 2026
and a standalone `appendix_a.pv` — were superseded by these three. They
remain in the git history at the tag `legacy-implementation`:

```bash
git checkout legacy-implementation -- proverif/
```
