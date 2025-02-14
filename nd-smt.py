# import hashlib
from circomlibpy.poseidon import PoseidonHash
import pprint
import sys
import random
import json

default = 0  # default 'empty' leaf

def dump(d):
    pprint.pp(d, width=220)

class CustomJSONEncoder(json.JSONEncoder):
    def encode(self, obj):
        return super().encode(obj).replace("\n        ", " ").replace("\n    ]", "]").replace("     ", " ")

def jdump(d):
    return json.dumps(d, cls=CustomJSONEncoder, indent=4)

poseidon = PoseidonHash()
def hash(left, right):
    if left == default and right == default:
        return default
    else:
        return poseidon.hash(2, [left, right])


class SparseMerkleTree:
    def __init__(self, depth=256):
        self.depth = depth
        self.nodes = {}
        self.default = [default] * (depth + 1)
        # Precompute default hashes for each level
        for i in range(1, depth + 1):
            self.default[i] = hash(self.default[i-1], self.default[i-1])


    def get_root(self):
        return self.get_node(self.depth, '')

    def get_node(self, level, path):
        return self.nodes.get((level, path), self.default[level])

    def update_node(self, level, path, value):
        if level == 0 and not (self.nodes.get((0, path)) is None):
            print(f"The leaf '{path}' is already set", file=sys.stderr)
            return
        self.nodes[(level, path)] = value

    def insert(self, key, value):
        path = self.key_to_bits(key)
        current = value
        self.update_node(0, path, current)

        for level in range(1, self.depth + 1):
            parent_path = path[:-level] if level < self.depth else ''
            bit = path[-level] if level <= len(path) else '0'

            if bit == '0':
                left = current
                right = self.get_node(level-1, parent_path + '1')
            else:
                left = self.get_node(level-1, parent_path + '0')
                right = current

            current = hash(left, right)
            self.update_node(level, parent_path, current)
        return current

    def generate_inclusion_proof(self, key):
        # returns inclusion proof for existing key
        # returns non-inclusion proof for unknown key
        #     that is, the default leaf
        path = self.key_to_bits(key)
        proof = []
        current_path = path

        for level in range(self.depth):
            parent_path = current_path[:-1] if level < self.depth-1 else ''
            last_bit = current_path[-1] if current_path else '0'

            if last_bit == '0':
                sibling_path = parent_path + '1'
            else:
                sibling_path = parent_path + '0'

            sibling_node = self.get_node(level, sibling_path)
            proof.append(sibling_node)
            current_path = parent_path

        return proof

    def missing_keys(self, keys):
        # take all chains of siblings
        # make unique
        # remove keys
        # remove prefixes
        def sibling_paths(path):
            paths = []
            current_path = path

            for level in range(self.depth):
                parent_path = current_path[:-1] if level < self.depth-1 else ''
                last_bit = current_path[-1] if current_path else '0'

                if last_bit == '0':
                    sibling_path = parent_path + '1'
                else:
                    sibling_path = parent_path + '0'

                paths += [sibling_path]
                current_path = parent_path

            return paths

        def prefix_free(bitstrings):
            result = set()
            for s in sorted(bitstrings, key=lambda x: (len(x), x)):
                if not any(other.startswith(s) and other != s for other in bitstrings):
                    result.add(s)

            return result

        siblings = []
        paths = []
        for key in keys:
            path = self.key_to_bits(key)
            siblings += sibling_paths(path)
            paths += [path]

        siblings = set(siblings) - set(paths)
        siblings = prefix_free(siblings)
        return siblings

    def verify_inclusion_proof(self, key, value, proof):
        path = self.key_to_bits(key)
        current = value

        for level in range(self.depth):
            sibling = proof[level]
            bit = path[-level-1] if level < len(path) else '0'

            if bit == '0':
                current = hash(current, sibling)
            else:
                current = hash(sibling, current)

        return current

    def verify_non_inclusion_proof(self, key, proof):
        path = self.key_to_bits(key)
        current = self.default[0]  # Start with the default leaf node

        for level in range(self.depth):
            sibling = proof[level]
            bit = path[-level-1] if level < len(path) else '0'

            if bit == '0':
                current = hash(current, sibling)
            else:
                current = hash(sibling, current)

        return current

    def key_to_bits(self, key):
        # Convert key to a string of 'depth' bits
        #return format(int.from_bytes(key, 'big'), '0{}b'.format(self.depth))
        return format(key, '0{}b'.format(self.depth))

    def batch_insert(self, keys, values):
        proof = {}
        # proof of consistency: collect all siblings necessary to compute root
        # based on new batch of keys
        # 'default' leaves are NOT included
        for k in self.missing_keys(keys):
            level = self.depth - len(k)
            if level >= self.depth or level < 0:
                raise ValueError(f"Panic, level {level} out of range")
            v = self.get_node(level, k)
            if v != default:
                proof[k] = v

        # Perform all insertions
        for key, value in zip(keys, values):
            self.insert(key, value)

        # invariant: the proof is the same if generated here again

        return proof

    def verify_non_deletion(self, proof, old_root, new_root, keys, values):
        def compute_forest(forest, path):
            for level in reversed(range(self.depth+1)):
                last_parent = None
                for k in sorted([key for key in forest if len(key) == level]):
                    parent = k[:-1]
                    if parent == last_parent:
                        continue
                    sibling = k[:-1] + ('1' if k[-1] == '0' else '0')
                    pv = hash(forest[k], forest.get(sibling, default)) if k[-1] == '0' else hash(forest.get(sibling, default), forest[k])
                    if parent in forest:
                        print(f"redundant parent {parent} in proof", file=sys.stderr)
                        if forest[parent] != pv:
                            raise Exception(f"parent mismatch {parent}->{forest[parent]}/{pv} in proof")
                    if parent == path:
                        return pv
                    forest[parent] = pv
                    last_parent = parent
            return False

        # step 1. compute old root based on proof and 'empty' leaves in place of new batch
        p1 = proof.copy()
        for key in keys:
            p1[self.key_to_bits(key)] = self.default[0]

        r1 = compute_forest(p1, '')
        if r1 != old_root:
            print(f"Non-deletion proof root mismatch: r:{r1}, oldr:{old_root}", file=sys.stderr)
            #return False

        # step 2. compute new root based on proof and leaves from the batch
        p2 = proof.copy()
        for key, value in zip(keys, values):
            p2[self.key_to_bits(key)] = value

        r2 = compute_forest(p2, '')
        if r2 != new_root:
            print(f"Non-deletion proof root mismatch: r:{r1}, newr:{new_root}", file=sys.stderr)
            return False

        # it is possible to compute the root based on
        #   1. empty leaves and the proof - giving the root before batch insertion,
        #   2. leaves in the batch and the proof - giving the root after batch insertion
        #  with the proof content being exactly the same.
        #  Proof is the roots of hash subtrees which did not change during the insertion
        #  thus only the leaves given in the batch did change, everything else is the same
        # and because we explicitly marked the leaves to be added as blank (default) before
        #  the first check, we know that these leaves were blank before inserting the batch,
        #  thus nothing was overwritten
        return True

    def prepare_witness(self, forest, keys, values, width):

        def deptharray(dict):
            # returns the matrix [level][keys]
            result = [[] for _ in range(self.depth + 1)]
            for key, value in sorted(dict.items()):
                keylen = len(key)
                result[keylen].append(key)
            return result

        # (var naming)   k-v dict    matrix[layer]  output array
        #                --------    ------         ------------
        # input batch:   kv          bm             batch[self.depth]
        # proof:         forest      fm             proof
        #
        kv = {self.key_to_bits(key): value for key, value in zip(keys, values)}

        bm = deptharray(kv)
        fm = deptharray(forest)

        # returned witness + instance
        wiringL = [[0] * width for _ in range(self.depth)]
        wiringR = [[0] * width for _ in range(self.depth)]
        proof = []
        batch = [[] for _ in range(self.depth+1)]
        # collect some statistics: width utilized and number of proof elements used at every layer
        stats = [0 for _ in range(self.depth)]
        stats2 = [0 for _ in range(self.depth)]
        for level in reversed(range(1, self.depth+1)):
            for w in range(width+1): # loop over cells, one too wide to catch overflow

                if len(bm[level]) <= 0:
                    stats[level-1] = w  # number includes zeroth cell
                    break
                k = bm[level].pop(0)

                if w >= width:
                    raise OverflowError(f"Circuit width overflow. w: {w}, level: {level}")

                batch[level].append(kv.get(k, None))  # append value to output vector

                sibling = k[:-1] + ('1' if k[-1] == '0' else '0')
                # check if there is sibling provided in proof
                sv = forest.get(sibling, None)
                if sv is None:
                    if len(bm[level]) > 0 and bm[level][0] == sibling:  # see if next input is the sibling
                        k2 = bm[level].pop(0)
                        if k[-1] == '0':
                            # index of 1st element is 1 because 0 is hardwired to 'empty'
                            wiringL[level-1][w] = len(batch[level])
                            batch[level].append(kv.get(k2, None))
                            wiringR[level-1][w] = len(batch[level])
                        else:
                            wiringR[level-1][w] = len(batch[level])
                            batch[level].append(kv.get(k2, None))
                            wiringL[level-1][w] = len(batch[level])
                    else:
                        # no sibling provided - thus "empty";
                        if k[-1] == '0':
                            wiringL[level-1][w] = len(batch[level])
                            wiringR[level-1][w] = 0
                        else:
                            wiringR[level-1][w] = len(batch[level])
                            wiringL[level-1][w] = 0
                else:
                    # sibling from proof
                    stats2[level] = stats2[level] + 1
                    proof.append(sv)
                    if k[-1] == '0':
                        wiringL[level-1][w] = len(batch[level])
                        wiringR[level-1][w] = len(proof) + width

                    else:
                        wiringR[level-1][w] = len(batch[level])
                        wiringL[level-1][w] = len(proof) + width
                parent = k[:-1]
                bm[level-1].append(parent)

        print("Proof usage:", stats2, file=sys.stderr)
        print("Cell  usage:", stats, "Inputs:", len(batch[self.depth]), "Proof:", len(proof), file=sys.stderr)

        return (batch[self.depth], proof, wiringL, wiringR)


def main():
    depth = 32
    width = 20

    def to_int(aa):
        if isinstance(aa, (list, tuple)):
            return [to_int(a) for a in aa]
        elif isinstance(aa, bytes):
            return int.from_bytes(aa, byteorder='big')
        else:
            return to_int(str(aa).encode())

    def to_bytes(bb):
        return str(bb).encode()

    def pad(aa, l):
        if len(aa) > l:
            raise OverflowError("too long")
        return [f"""{a}""" for a in aa] + ["0"] * (l - len(aa))

    def js(a):
        # json strings are safer than long ints
        return f"""{a}"""

    smt = SparseMerkleTree(depth)

    keys = to_int([b'\x01', b'\x02', b'\x05'])
    values = to_int([b'value1', b'value2', b'value5'])
    old_root = smt.get_root()
    proof = smt.batch_insert(keys, values)
    new_root = smt.get_root()
    assert smt.verify_non_deletion(proof, old_root, new_root, keys, values)

    # keys = [b'\x03', b'\x0a', b'\x0b', b'\x0c']
    # values = [b'value3', b'value0a', b'value0b', b'value0c']
    keys = []
    values = []
    for i in range(32):
        ri = random.randint(0, 2**depth-1)
        if ri in keys:
            break
        keys.append(ri)
        values.append(to_int(("Val " + str(ri)).encode()))

    proof = smt.batch_insert(keys, values)
    new_root = smt.get_root()

    keys = []
    values = []
    for i in range(20):
        ri = random.randint(0, 2**depth-1)
        p = smt.key_to_bits(ri)
        if ri in keys:
            break
        keys.append(ri)
        values.append(to_int(("Val " + str(ri)).encode()))

    proof = smt.batch_insert(keys, values)
    new_new_root = smt.get_root()
    assert smt.verify_non_deletion(proof, new_root, new_new_root, keys, values)
    batch, proof, wiringL, wiringR = smt.prepare_witness(proof, keys, values, width)

    # witness formatted as json
    jsond = jdump({'batch': pad(batch, width), 'proof': pad(proof, depth),
                           'controlL': wiringL, 'controlR': wiringR,
                           'root1': js(new_root), 'root2': js(new_new_root)})
    print(jsond)


if __name__ == "__main__":
    main()