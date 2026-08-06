# What a conformance result lets you say

A passing run is a self-test. It is evidence that an implementation behaved correctly against a
named set of fixtures, and it is nothing else. This page exists because the gap between those two
statements is where honest projects usually go wrong.

## The one permitted claim

> Self-tested as PASS against Decision Replay Conformance Profile v1, fixture manifest
> `<sha256>`, using runner `<version>`, implementation `<name> <version>`.

All four identifiers are part of the claim. A result quoted without them says nothing: fixtures can
change, and a digest is what makes a past result checkable.

## Claims that are not permitted

Do not say, or imply, that a passing result means the implementation is:

- certified, accredited, approved, or endorsed by anyone;
- compliant with any law, regulation, standard body, or contract;
- secure, safe for consequential use, or free of defects;
- equivalent in every respect to `verify-run` or to any other implementation.

Nobody accredits this profile. The maintainers of `verify-run` do not review, audit, or endorse
another implementation's self-test, and publishing a result does not create a relationship.

## Badges

A badge is permitted only if the profile version and the fixture-manifest digest are displayed
beside it, in text a reader can copy. A static badge that says "conformant" without them is
misleading, because it survives changes that should have invalidated it. Until that is designed
properly, this project ships no badge image.

## Publishing a result

Publish the result document itself, not a summary of it. It carries the profile digest, the fixture
digest, the runner version, the implementation version, the per-requirement status, and the
declaration that it is a self-report. A reader who has the fixtures can re-run it.

## What the profile deliberately does not establish

The full list is §16 of the normative contract. The short version: verification tells you the
record is authentic and that its recorded decision follows from its recorded inputs. It tells you
nothing about whether the evidence was true, whether the rulebook was wise, whether the authority
was legitimate, or whether the action's effects occurred in the world.
