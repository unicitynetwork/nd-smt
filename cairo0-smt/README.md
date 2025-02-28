# Problem

Problem is the same: proving correct operation of an append-only dictionary. Using Cairo Zero and STARKs.

# Walkthrough

```sh
# Use python 3.9
python3.9 -m venv venv
source venv/bin/activate
# Install Cairo 0.x, also known as Cairo Zero
pip3 install cairo-lang

cairo-compile --proof_mode cairo0-ver.cairo --output cairo0-ver.json

# modify batch size, tree pre-population; produce an input file with synthetic batch of transactions:
python3 ndsmt.py > cairo_input.json

# run, produce execution trace and memory dump
cairo-run --layout recursive_with_poseidon --print_output --program cairo0-ver.json --program_input cairo_input.json --air_public_input ver_pub_in.json  --air_private_input ver_priv_in.json --trace_file ver_trace.bin --memory_file ver_memory.bin --proof_mode

# get stone prover from https://github.com/starkware-libs/stone-prover

# optimal prover parameters for specific transcript size
python3 ../stone-prover/gen_stone_params.py ver_pub_in.json > cpu_air_params.json
# reducing PoW bits makes proving faster (at the cost of minor proof size increase)

cpu_air_prover --out_file ver_proof.json --private_input_file ver_priv_in.json   --public_input_file ver_pub_in.json --prover_config_file cpu_air_prover_config.json --parameter_file cpu_air_params.json

cpu_air_verifier --in_file ver_proof.json || echo Broken
```
Have a look at the `ver_proof.jsom` file; if the public inputs are as expected, then the program execution given these public and unknown, but appropriate private inputs is ``proven'' to be successful. But which program? stone prover's verifier does not care. Another look shows, that stone prover does not care about leaking private input to the proof either. Go figure.