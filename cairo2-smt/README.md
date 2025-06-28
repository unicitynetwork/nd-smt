# Problem

Prove non-deletion of SMT operation rounds.

Using the latest version of Cairo language and bleeding edge toolchain.

Hash function is Poseidon, prover is S-Two using Circle-STARK.

# Walkthrough

```sh
# Generate testdata
pip3 install -r requirements.txt
python3 smt.py > input.json

# install scarb: https://docs.swmansion.com/scarb/download.html
# preferably nightly, and note that Mac's brew package misses 'scarb execute'
scarb --version    # test if scarb works
# Build, run, prove, verify
python3 run_verifier.py
```

# Notes

 * Modify numbers at the end of smt.py to change proving batch size or SMT pre-fill
 * `export RAYON_NUM_THREADS=xx`  # be more specific with multi-threading
 * https://github.com/starkware-libs/stwo-cairo is a bit more stable than `scarb prove`
 * run_verifier.py converts input.json to "cairo serde" format, which is ... different json.
 * All inputs have to fit into felt252 (be less than $P = 2^{251} + 17 \times 2^{192} + 1$)
 * All Poseidons are not the same, the underlying field and instantiation parameters must match. We're using Poseidon's compression function directly.
 * It is an exploration.
