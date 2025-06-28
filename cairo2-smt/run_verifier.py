import json
import subprocess
import tempfile
import os
import time

def to_cairo_serde(fn):
    try:
        with open(fn, 'r') as f:
            data = json.load(f)
    except FileNotFoundError:
        print(f"{fn} does not exist. Create one by running 'python3 smt.py > {fn}'.")
        exit(-1)

    cairo_args_list = []

    def to_hex(val):
        return hex(val)

    cairo_args_list.append(to_hex(data["old_root"]))
    cairo_args_list.append(to_hex(data["new_root"]))

    # batch: Array<(u32, felt252)>
    cairo_args_list.append(to_hex(len(data["batch"]))) # Length of batch
    for key, value in data["batch"]:
        cairo_args_list.append(to_hex(key))
        cairo_args_list.append(to_hex(value))

    # proof: Array<Array<(u32, felt252)>>
    cairo_args_list.append(to_hex(len(data["proof"]))) # Length of proof (outer array)
    for inner_proof_array in data["proof"]:
        cairo_args_list.append(to_hex(len(inner_proof_array))) # Length of inner array
        for key, value in inner_proof_array:
            cairo_args_list.append(to_hex(key))
            cairo_args_list.append(to_hex(value))

    # depth: u32
    cairo_args_list.append(to_hex(data["depth"]))

    return cairo_args_list

def run_command(command, description):
    print(f"\n--- {description} ---")
    print(f"Running command: {' '.join(command)}")
    start_time = time.time()
    result = subprocess.run(command, capture_output=True, text=True)
    end_time = time.time()
    print(f"Time taken: {end_time - start_time:.2f} seconds")

    print("Stdout:")
    print(result.stdout)
    print("Stderr:")
    print(result.stderr)

    if result.returncode != 0:
        print(f"Command exited with error code {result.returncode}")
        exit(result.returncode)
    return result

def main():

    cairo_args = to_cairo_serde('input.json')

    # Write the cairo serde format input to a temp file
    with tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.json') as temp_arg_file:
        json.dump(cairo_args, temp_arg_file)
        temp_arg_file_path = temp_arg_file.name

    # 1. Build the Cairo program
    run_command(["scarb", "build"], "Building Cairo program")

    # 2. Execute the Cairo program to generate trace etc
    execute_result = run_command([
        "scarb",
        "execute",
        "--no-build",
        "--target", "standalone",
        "--package", "zk_verifier",
        "--print-resource-usage",
        "--arguments-file", temp_arg_file_path,
    ], "Executing Cairo program to generate trace")

    # Extract the execution ID from the execute command output
    execution_id = None
    for line in execute_result.stdout.splitlines():
        if "Saving output to:" in line:
            execution_id = os.path.basename(line.split("Saving output to:")[1].strip()).replace("execution", "")
            break

    if not execution_id:
        print("Error: Could not find execution ID in scarb execute output.")
        exit(1)

    # 3. Prove
    prove_result = run_command([
        "scarb",
        "prove",
        "--package", "zk_verifier",
        "--execution-id", execution_id,
    ], "Generating proof")

    proof_file_path = f"target/execute/zk_verifier/execution{execution_id}/proof/proof.json"

    # 4. Verify
    run_command(["scarb", "verify", "--proof-file", proof_file_path], "Verifying proof")

    os.remove(temp_arg_file_path)

if __name__ == "__main__":
    main()
