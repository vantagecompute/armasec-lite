"""
The comparison harness's load generator and scenario driver.

Standard library only, and it imports neither library under test. Every measurement is
taken from outside the two application processes, over the network, by a client that has no
knowledge of what is running inside them.

`run.py` is the driver, `scenarios.py` holds the load generator and the scenarios, and
`report.py` holds provenance, statistics and result-file writing.
"""
