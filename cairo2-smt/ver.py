import json
import sys
from smt import verify_non_deletion

fn = sys.argv[1] if len(sys.argv) > 1 else 'input.json'
with open(fn) as f:
    d = json.load(f)
    assert(verify_non_deletion(d['proof'], d['old_root'], d['new_root'], d['batch'], d['depth']))
    print("okay")
