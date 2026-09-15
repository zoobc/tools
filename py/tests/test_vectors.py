# SPDX-License-Identifier: MIT
# Copyright (c) 2024-2026 ZooBC Foundation and Roberto Capodieci
"""Every file in spec/vectors, run through the library and through zbc-cli. python3 -m unittest -v (from py/)."""
import json
import os
import pathlib
import subprocess
import sys
import unittest

ROOT = pathlib.Path(__file__).resolve().parent.parent.parent
V = ROOT / "spec" / "vectors"
sys.path.insert(0, str(ROOT / "py"))
import zbc  # noqa: E402
from zbc import _commands  # noqa: E402

CLI = [sys.executable, "-m", "zbc.cli"]
ENV = {k: v for k, v in os.environ.items() if k not in ("ZBC_KEY", "ZBC_API", "ZBC_TIMEOUT", "ZOOBC_GENESIS_HASH")}


def load(name):
    return json.loads((V / name).read_text())


def run_cli(args, stdin=None, env=None):
    p = subprocess.run(CLI + args, input=stdin, capture_output=True, text=True, env=env or ENV, cwd=str(ROOT / "py"))
    return p.returncode, p.stdout, p.stderr


def envelope(v, body):
    spec = _commands.COMMAND_BY_NAME[v["command"]]
    sender = zbc.key_pair(v["key"])
    recipient = zbc.parse_address(v["params"]["recipient"]).bytes if spec["recipient"] == "required" else b""
    escrow = zbc.Escrow(**v["escrow"]) if v.get("escrow") else None
    return zbc.sign_transaction(v["type"], v["timestamp"], sender, recipient, v["fee"], body, zbc.SigningContext.of(v["genesis"]),
                                escrow, (v.get("message") or "").encode())


class Vectors(unittest.TestCase):
    def check_signed(self, v, signed):
        e = v["expected"]
        self.assertEqual(signed.unsigned.hex(), e["unsigned_bytes"], v["name"])
        self.assertEqual(signed.digest.hex(), e["digest"], v["name"])
        self.assertEqual(signed.signature.hex(), e["signature"], v["name"])
        self.assertEqual(signed.bytes.hex(), e["transaction_bytes"], v["name"])
        self.assertEqual(signed.hash.hex(), e["transaction_hash"], v["name"])
        self.assertEqual(signed.payload, e["payload"], v["name"])

    def test_keys(self):
        d = load("keys.json")
        for s in d["seeds"]:
            kp = zbc.key_pair(s["seed"])
            self.assertEqual(kp.public_key.hex(), s["public_key"])
            self.assertEqual(kp.address, s["address"])
            self.assertEqual(kp.node_address, s["node_address"])
        for w in d["wallets"]:
            self.assertTrue(zbc.validate_mnemonic(w["mnemonic"]))
            for a in w["accounts"]:
                acct = zbc.wallet_account(w["mnemonic"], a["index"], w["passphrase"])
                self.assertEqual((acct.path, acct.seed.hex(), acct.address, acct.node_address), (a["path"], a["seed"], a["address"], a["node_address"]))

    def test_addresses(self):
        for v in load("addresses.json")["vectors"]:
            if v["valid"]:
                p = zbc.parse_address(v["input"], v.get("chain", ""))
                self.assertEqual((p.type, p.bytes.hex()), (v["account_type"], v["address_bytes"]), v["input"])
            else:
                with self.assertRaises(ValueError, msg=v["input"]):
                    zbc.parse_address(v["input"], v.get("chain", ""))

    def test_messages(self):
        m = load("messages.json")
        for v in m["vectors"]:
            s = zbc.sign_message(v["seed"], bytes.fromhex(v["message_hex"]))
            self.assertEqual((s["address"], s["public_key"], s["digest"], s["signature"]), (v["address"], v["public_key"], v["digest"], v["signature"]))
            self.assertTrue(zbc.verify_message(v["address"], bytes.fromhex(v["message_hex"]), v["signature"]))
        for n in m["invalid"]:
            self.assertFalse(zbc.verify_message(n["address"], n["message"].encode(), n["signature"]), n["case"])

    def test_core_transactions(self):
        for v in load("transactions.json")["vectors"]:
            if v["command"] == "send-zbc":
                body = zbc.send_zbc_body(int(v["params"]["amount"]))
            else:
                body = zbc.approval_escrow_body(int(v["params"]["approval"]), bytes.fromhex(v["params"]["transaction_hash"]))
            self.assertEqual(body.hex(), v["expected"]["body"], v["name"])
            self.check_signed(v, envelope(v, body))

    def test_all_transaction_types(self):
        for v in load("transactions-all.json")["vectors"]:
            spec = _commands.COMMAND_BY_NAME[v["command"]]
            sender = zbc.key_pair(v["key"])
            ctx = zbc.SigningContext.of(v["genesis"])
            if spec["custom"] in ("multisig", "settle"):
                body, _ = zbc.custom_body(spec, dict(v["params"]), sender, ctx, v["timestamp"])
            else:
                computed = {}
                ref = (bytes.fromhex(v["reference_block"]["block_hash"]), v["reference_block"]["height"]) if v.get("reference_block") else None
                zbc.compute_fields(spec, dict(v["params"]), sender, computed, ref)
                files = {k: bytes.fromhex(h) for k, h in (v.get("files") or {}).items()}
                body = zbc.build_body(spec, v["params"], sender, files, computed)
            self.assertEqual(body.hex(), v["expected"]["body"], v["name"])
            self.check_signed(v, envelope(v, body))

    def test_transaction_id(self):
        self.assertEqual(zbc.transaction_id(bytes.fromhex("4ac2d11be8fe534bf2b2776fa7c1a3ece08e17f3b71e8d796545f5edde8b86fa")), 5427962248764179018)

    def test_cli_offline_reproduces_every_vector(self):
        for v in load("transactions.json")["vectors"] + load("transactions-all.json")["vectors"]:
            spec = _commands.COMMAND_BY_NAME[v["command"]]
            if spec["needs_node"] or any(p["kind"] == "file" for p in spec["params"]):
                continue
            args = [v["command"], v["key"]] + [v["params"].get(p["name"], p.get("default", "")) for p in spec["params"][1:]
                                              if not (v["command"] == "liquid-payment" and p["name"] == "token_id")]
            args += ["--fee", str(v["fee"]), "--timestamp", str(v["timestamp"]), "--genesis", v["genesis"], "--offline"]
            if v.get("message"):
                args += ["--message", v["message"]]
            if v.get("escrow"):
                e = v["escrow"]
                args += ["--escrow-approver", e["approver"], "--escrow-commission", str(e["commission"]), "--escrow-timeout", str(e["timeout"])]
                if e.get("instruction"):
                    args += ["--escrow-instruction", e["instruction"]]
            if v["command"] == "liquid-payment" and v["params"].get("token_id", "0") != "0":
                args += ["--token", v["params"]["token_id"]]
            rc, out, err = run_cli(args)
            self.assertEqual(rc, 0, "%s: %s%s" % (v["name"], out, err))
            j = json.loads(out)
            self.assertEqual(j["transaction_hash"], v["expected"]["transaction_hash"], v["name"])
            self.assertEqual(j["payload"], v["expected"]["payload"], v["name"])

    def test_cli_exit_codes(self):
        for c in load("cli.json")["vectors"]:
            rc, out, err = run_cli(c["args"], stdin=c.get("stdin"))
            self.assertEqual(rc, c["exit_code"], "%s: %s%s" % (c["case"], out, err))
            if c.get("error_class"):
                self.assertEqual(json.loads(out)["error_class"], c["error_class"], c["case"])

    def test_cli_messages(self):
        m = load("messages.json")
        for v in m["vectors"]:
            hexflag = ["--hex"] if v["hex_input"] else []
            msg = v["message_hex"] if v["hex_input"] else v["message"]
            rc, out, _ = run_cli(["sign-message", v["seed"], msg] + hexflag)
            self.assertEqual(rc, 0)
            self.assertEqual(json.loads(out)["signature"], v["signature"])
            rc, out, _ = run_cli(["verify-message", v["address"], msg, v["signature"]] + hexflag)
            self.assertEqual((rc, json.loads(out)["valid"]), (0, True))
        for n in m["invalid"]:
            rc, out, _ = run_cli(["verify-message", n["address"], n["message"], n["signature"]])
            self.assertEqual(rc, n["exit_code"], n["case"])

    def test_cli_json_input_and_env_key(self):
        v = load("transactions.json")["vectors"][0]
        stdin = json.dumps({"sender_privkey": v["key"], "recipient": v["params"]["recipient"], "amount": v["params"]["amount"],
                            "fee": v["fee"], "timestamp": v["timestamp"], "offline": True})
        rc, out, err = run_cli(["send-zbc", "--json-input", "--genesis", v["genesis"]], stdin=stdin)
        self.assertEqual(rc, 0, out + err)
        self.assertEqual(json.loads(out)["transaction_hash"], v["expected"]["transaction_hash"])
        env = dict(ENV, ZBC_KEY=v["key"])
        for args in ([v["params"]["recipient"], v["params"]["amount"]], ["-", v["params"]["recipient"], v["params"]["amount"]]):
            rc, out, err = run_cli(["send-zbc"] + args + ["--timestamp", str(v["timestamp"]), "--genesis", v["genesis"], "--offline"], env=env)
            self.assertEqual(rc, 0, out + err)
            self.assertEqual(json.loads(out)["transaction_hash"], v["expected"]["transaction_hash"])


if __name__ == "__main__":
    unittest.main()
