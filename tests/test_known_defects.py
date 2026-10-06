"""Known defects: what `CHANGELOG.md` lists under that heading, one saved message each.

A defect that is known and not yet fixed is stated here as the contract states it, and marked
as an expected failure — strictly, so the day it is fixed the test fails until the mark and
the entry in `CHANGELOG.md` are removed. An entry cannot outlive its defect, and a defect
cannot be forgotten by being fixed in passing.

An expected failure is satisfied by any failure, which is the trap of this file: a broken
fixture would keep it green for ever. So each defect comes with a control that is an ordinary
test — the same material, one step away from the defect, where the service does what the
contract says — and the mark accepts an `AssertionError` and nothing else.

None is known at the moment. The last one, a defanged form directly after a hyphen or a period,
was fixed in 0.7.0 by `[D28]`, and its test and control are ordinary ones in `test_defanged.py`.
"""
