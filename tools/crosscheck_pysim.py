"""Optional cross-check against the SCP02/SCP03 test vectors published in osmocom pySim.

pySim is GPL-2.0-or-later, so none of its code or data is copied into this
Apache-2.0 repository. You clone pySim yourself; this script reads its test
file with `ast` (pySim is never imported or executed) and recomputes every
expected value with this package.

    git clone https://gitea.osmocom.org/sim-card/pysim.git
    git -C pysim checkout 0c4d170e773798c390abe996aa089791192e28ce
    python tools/crosscheck_pysim.py pysim

Exit status: 0 = every value matched, 1 = a mismatch, 2 = the file could not be read.
"""
import ast
import subprocess
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from gp_secure_channel import apdu, scp02, scp03  # noqa: E402

PINNED_COMMIT = "0c4d170e773798c390abe996aa089791192e28ce"
TEST_FILE = "tests/unittests/test_globalplatform.py"
SCP03_CLASSES = ("SCP03_Test_AES128_11", "SCP03_Test_AES128_03", "SCP03_Test_AES128_33")  # AES-128 only


def value(node, env):
    """Evaluate the few literal forms the test file uses: h2b('..'), names, GpCardKeyset(...)."""
    if isinstance(node, ast.Constant):
        return node.value
    if isinstance(node, ast.Name):
        return env[node.id]
    if isinstance(node, ast.Call) and isinstance(node.func, ast.Name):
        args = [value(a, env) for a in node.args]
        if node.func.id == "h2b":
            return bytes.fromhex(args[0])
        if node.func.id == "GpCardKeyset":
            return tuple(args)                                  # (kvn, enc, mac, dek)
    raise ValueError(f"unexpected expression at line {node.lineno}")


def assigns(body, env):
    out = {}
    for stmt in body:
        if isinstance(stmt, ast.Assign) and isinstance(stmt.targets[0], ast.Name):
            try:
                out[stmt.targets[0].id] = value(stmt.value, {**env, **out})
            except (ValueError, KeyError):
                pass                                            # not a literal; not needed
    return out


def method(cls, name):
    return next(f for f in cls.body if isinstance(f, ast.FunctionDef) and f.name == name)


def calls(fn, attr):
    return [n for n in ast.walk(fn) if isinstance(n, ast.Call) and getattr(n.func, "attr", None) == attr]


def load(path):
    tree = ast.parse(path.read_text())
    env = assigns(tree.body, {})
    classes = {c.name: c for c in tree.body if isinstance(c, ast.ClassDef)}
    attrs = {name: assigns(c.body, env) for name, c in classes.items()}
    return env, classes, attrs


def run(root):
    env, classes, attrs = load(root / TEST_FILE)
    results = []

    def check(label, ok):
        results.append(ok)
        print(f"{'PASS' if ok else 'FAIL'}  {label}")

    # SCP02, 3DES, i=55 style ICV encryption (pySim SCP02_Auth_Test + SCP02_Test)
    kvn, enc, mac, dek = env["ck_3des_70"]
    auth = attrs["SCP02_Auth_Test"]
    expected = [a.args[1].value for a in calls(method(classes["SCP02_Auth_Test"], "test_mutual_auth_success"), "assertEqual")]
    hc = auth["host_challenge"]
    check("SCP02 INITIALIZE UPDATE command", apdu.initialize_update(hc, kvn).hex().upper() == expected[0])
    iu = apdu.parse_initialize_update_scp02(auth["init_update_resp"])
    s = scp02.Session(enc, mac, dek, iu.sequence_counter, iu.card_challenge, hc)
    check("SCP02 card cryptogram", s.card_cryptogram == iu.card_cryptogram)
    check("SCP02 EXTERNAL AUTHENTICATE", s.external_authenticate().hex().upper() == expected[1])
    fn = method(classes["SCP02_Test"], "test_mac_command")
    plains = [value(c.args[0], env) for c in calls(fn, "wrap_cmd_apdu")]
    wraps = [c.args[1].value for c in calls(fn, "assertEqual")]
    if len(plains) != len(wraps) or len(expected) != 2:
        raise ValueError("unexpected SCP02 test layout")
    for n, (plain, want) in enumerate(zip(plains, wraps), 1):
        check(f"SCP02 C-MAC case {n}", s.wrap(plain).hex().upper() == want)

    # SCP03, AES-128, levels 11 / 03 / 33; same call order as pySim's shared-state test class
    base = attrs["SCP03_Test"]
    for name in SCP03_CLASSES:
        t = {**base, **attrs[name]}
        kvn, enc, mac, _dek = t["keyset"]
        hc, level = t["init_upd_cmd"][5:-1], t["ext_auth_cmd"][2]
        tag = f"SCP03 AES-128 level {level:02X}"
        check(f"{tag} INITIALIZE UPDATE command", apdu.initialize_update(hc, kvn) == t["init_upd_cmd"])
        iu = apdu.parse_initialize_update_scp03(t["init_upd_rsp"], expected_key_version=kvn)
        s = scp03.Session(enc, mac, hc, iu.card_challenge, level)
        check(f"{tag} card cryptogram", s.card_cryptogram == iu.card_cryptogram)
        check(f"{tag} EXTERNAL AUTHENTICATE", s.external_authenticate() == t["ext_auth_cmd"])
        check(f"{tag} wrapped GET EID", s.wrap(t["get_eid_cmd_plain"]) == t["get_eid_cmd"])
        check(f"{tag} unwrapped GET EID response",
              s.unwrap(t["get_eid_rsp"] + b"\x90\x00") == t["get_eid_rsp_plain"] + b"\x90\x00")
        for n in range(1, 5):
            check(f"{tag} case {n} APDU", s.wrap(t[f"case_{n}_apdu_plain"]) == t[f"case_{n}_apdu"])
    return results


def main():
    if len(sys.argv) != 2:
        print(__doc__)
        sys.exit(2)
    root = Path(sys.argv[1])
    try:
        commit = subprocess.run(["git", "-C", str(root), "rev-parse", "HEAD"],
                                capture_output=True, text=True, check=True).stdout.strip()
    except (OSError, subprocess.CalledProcessError):
        commit = "unknown (not a git checkout)"
    print(f"pySim commit: {commit}")
    if commit != PINNED_COMMIT:
        print(f"WARNING: not the pinned commit {PINNED_COMMIT}; results may differ")
    try:
        results = run(root)
    except (OSError, SyntaxError, KeyError, StopIteration, IndexError, AttributeError, ValueError) as e:
        print(f"ERROR: could not read the pySim test vectors: {e!r}")
        sys.exit(2)
    print(f"{sum(results)}/{len(results)} values match -> {'PASS' if all(results) else 'FAIL'}")
    sys.exit(0 if results and all(results) else 1)


if __name__ == "__main__":
    main()
