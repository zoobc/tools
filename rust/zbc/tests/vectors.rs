// SPDX-License-Identifier: MIT
// Copyright (c) 2024-2026 ZooBC Foundation and Roberto Capodieci

//! Every file in spec/vectors, through the library and in-process through the CLI.

use serde_json::Value;
use std::collections::HashMap;
use std::path::PathBuf;
use zbc::body::{build_body, BodyContext};
use zbc::cli::{run_with, Io};
use zbc::custom::{compute_fields, custom_body, CustomInput, ReferenceBlock};
use zbc::*;

fn load(name: &str) -> Value {
    let p = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../spec/vectors").join(name);
    serde_json::from_str(&std::fs::read_to_string(&p).unwrap_or_else(|_| panic!("{p:?}"))).unwrap()
}
fn s(v: &Value, k: &str) -> String {
    v[k].as_str().unwrap_or("").to_string()
}
fn params_of(v: &Value) -> HashMap<String, String> {
    v["params"].as_object().unwrap().iter().map(|(k, x)| (k.clone(), x.as_str().unwrap().to_string())).collect()
}

fn cli(args: &[&str], stdin: &str, env: &[(&str, &str)]) -> (i32, String, String) {
    let mut input = stdin.as_bytes();
    let (mut out, mut err) = (Vec::new(), Vec::new());
    let map: HashMap<String, String> = env.iter().map(|(k, v)| (k.to_string(), v.to_string())).collect();
    let getenv = |k: &str| map.get(k).cloned();
    let code = {
        let mut io = Io { stdin: &mut input, stdout: &mut out, stderr: &mut err, env: &getenv, is_tty: false };
        run_with(&args.iter().map(|a| a.to_string()).collect::<Vec<_>>(), &mut io)
    };
    (code, String::from_utf8(out).unwrap(), String::from_utf8(err).unwrap())
}

#[test]
fn keys_and_wallets() {
    let d = load("keys.json");
    for x in d["seeds"].as_array().unwrap() {
        let kp = KeyPair::from_hex(&s(x, "seed")).unwrap();
        assert_eq!(hex::encode(kp.public_key), s(x, "public_key"));
        assert_eq!(kp.address(), s(x, "address"));
        assert_eq!(kp.node_address(), s(x, "node_address"));
    }
    for w in d["wallets"].as_array().unwrap() {
        assert!(validate_mnemonic(&s(w, "mnemonic")));
        for a in w["accounts"].as_array().unwrap() {
            let (kp, path) = wallet_account(&s(w, "mnemonic"), a["index"].as_u64().unwrap() as u32, &s(w, "passphrase")).unwrap();
            assert_eq!(path, s(a, "path"));
            assert_eq!(hex::encode(kp.seed), s(a, "seed"));
            assert_eq!(kp.address(), s(a, "address"));
            assert_eq!(kp.node_address(), s(a, "node_address"));
        }
    }
}

#[test]
fn addresses() {
    for v in load("addresses.json")["vectors"].as_array().unwrap() {
        let input = s(v, "input");
        let chain = s(v, "chain");
        let r = parse_address(&input, &chain);
        if v["valid"].as_bool().unwrap() {
            let p = r.unwrap_or_else(|e| panic!("{input}: {e}"));
            assert_eq!(p.account_type as i64, v["account_type"].as_i64().unwrap(), "{input}");
            assert_eq!(hex::encode(p.bytes()), s(v, "address_bytes"), "{input}");
        } else {
            assert!(r.is_err(), "{input} accepted, reference refuses it");
        }
    }
}

#[test]
fn messages() {
    let d = load("messages.json");
    for v in d["vectors"].as_array().unwrap() {
        let kp = KeyPair::from_hex(&s(v, "seed")).unwrap();
        let msg = hex::decode(s(v, "message_hex")).unwrap();
        let sm = sign_message(&kp, &msg);
        assert_eq!((sm.address, sm.public_key, sm.digest, sm.signature.clone()), (s(v, "address"), s(v, "public_key"), s(v, "digest"), s(v, "signature")));
        assert!(verify_message(&s(v, "address"), &msg, &hex::decode(s(v, "signature")).unwrap()));
    }
    for n in d["invalid"].as_array().unwrap() {
        let sig = hex::decode(s(n, "signature")).unwrap_or_default();
        assert!(!verify_message(&s(n, "address"), s(n, "message").as_bytes(), &sig), "{}", s(n, "case"));
    }
}

fn check_signed(v: &Value, body: Vec<u8>) {
    let name = s(v, "name");
    let e = &v["expected"];
    assert_eq!(hex::encode(&body), s(e, "body"), "{name} body");
    let def = command(&s(v, "command")).unwrap();
    let kp = KeyPair::from_hex(&s(v, "key")).unwrap();
    let recipient = if def.recipient == "required" { parse_address(&s(&v["params"], "recipient"), "").unwrap().bytes() } else { Vec::new() };
    let escrow = v["escrow"].as_object().map(|e| Escrow {
        approver: e["approver"].as_str().unwrap().into(), commission: e["commission"].as_i64().unwrap(), timeout: e["timeout"].as_i64().unwrap(),
        instruction: e.get("instruction").and_then(Value::as_str).unwrap_or("").into(),
    });
    let tx = Unsigned { tx_type: v["type"].as_u64().unwrap() as u32, timestamp: v["timestamp"].as_i64().unwrap(), sender: kp.account_bytes(), recipient,
                        fee: v["fee"].as_i64().unwrap(), body, escrow, message: v["message"].as_str().unwrap_or("").as_bytes().to_vec(), version: 1 };
    let signed = sign_transaction(&tx, &kp, &SigningContext::of(&s(v, "genesis")).unwrap()).unwrap();
    assert_eq!(hex::encode(&signed.unsigned), s(e, "unsigned_bytes"), "{name}");
    assert_eq!(hex::encode(signed.digest), s(e, "digest"), "{name}");
    assert_eq!(hex::encode(signed.signature), s(e, "signature"), "{name}");
    assert_eq!(hex::encode(&signed.bytes), s(e, "transaction_bytes"), "{name}");
    assert_eq!(hex::encode(signed.hash), s(e, "transaction_hash"), "{name}");
    assert_eq!(serde_json::to_value(&signed.payload).unwrap(), e["payload"], "{name} payload");
}

#[test]
fn core_transactions() {
    for v in load("transactions.json")["vectors"].as_array().unwrap() {
        let p = params_of(v);
        let body = if s(v, "command") == "send-zbc" {
            send_zbc_body(p["amount"].parse().unwrap())
        } else {
            approval_escrow_body(p["approval"].parse().unwrap(), &hex::decode(&p["transaction_hash"]).unwrap()).unwrap()
        };
        check_signed(v, body);
    }
}

#[test]
fn all_transaction_types() {
    for v in load("transactions-all.json")["vectors"].as_array().unwrap() {
        let def = command(&s(v, "command")).unwrap();
        let params = params_of(v);
        let kp = KeyPair::from_hex(&s(v, "key")).unwrap();
        let ctx = SigningContext::of(&s(v, "genesis")).unwrap();
        let block = v["reference_block"].as_object().map(|b| ReferenceBlock { hash: hex::decode(b["block_hash"].as_str().unwrap()).unwrap(), height: b["height"].as_u64().unwrap() as u32 });
        let input = CustomInput { def, params: &params, sender: &kp, ctx: &ctx, timestamp: v["timestamp"].as_i64().unwrap(), block: block.as_ref() };
        let body = if matches!(def.custom.as_deref(), Some("multisig") | Some("settle")) {
            custom_body(&input).unwrap().0
        } else {
            let mut bc = BodyContext { sender: Some(kp.clone()), ..Default::default() };
            if let Some(files) = v["files"].as_object() {
                for (k, h) in files {
                    bc.files.insert(k.clone(), hex::decode(h.as_str().unwrap()).unwrap());
                }
            }
            compute_fields(&input, &mut bc).unwrap();
            build_body(def, &params, &bc).unwrap()
        };
        check_signed(v, body);
    }
}

#[test]
fn transaction_id_is_int64_le() {
    assert_eq!(zbc::transaction::transaction_id(&hex::decode("4ac2d11be8fe534bf2b2776fa7c1a3ece08e17f3b71e8d796545f5edde8b86fa").unwrap()), 5427962248764179018);
}

#[test]
fn cli_offline_reproduces_every_vector() {
    let mut all = load("transactions.json")["vectors"].as_array().unwrap().clone();
    all.extend(load("transactions-all.json")["vectors"].as_array().unwrap().clone());
    for v in &all {
        let def = command(&s(v, "command")).unwrap();
        if def.needs_node || def.params.iter().any(|p| p.kind == "file") {
            continue;
        }
        let params = params_of(v);
        let mut args: Vec<String> = vec![def.command.clone(), s(v, "key")];
        for p in &def.params[1..] {
            if def.command == "liquid-payment" && p.name == "token_id" {
                continue;
            }
            args.push(params.get(&p.name).cloned().or_else(|| p.default.clone()).unwrap_or_default());
        }
        args.extend(["--fee".into(), v["fee"].to_string(), "--timestamp".into(), v["timestamp"].to_string(), "--genesis".into(), s(v, "genesis"), "--offline".into()]);
        if let Some(m) = v["message"].as_str() {
            args.extend(["--message".into(), m.into()]);
        }
        if let Some(e) = v["escrow"].as_object() {
            args.extend(["--escrow-approver".into(), e["approver"].as_str().unwrap().into(), "--escrow-commission".into(), e["commission"].to_string(), "--escrow-timeout".into(), e["timeout"].to_string()]);
            if let Some(i) = e.get("instruction").and_then(Value::as_str).filter(|i| !i.is_empty()) {
                args.extend(["--escrow-instruction".into(), i.into()]);
            }
        }
        if def.command == "liquid-payment" && params.get("token_id").is_some_and(|t| t != "0") {
            args.extend(["--token".into(), params["token_id"].clone()]);
        }
        let refs: Vec<&str> = args.iter().map(String::as_str).collect();
        let (code, out, err) = cli(&refs, "", &[]);
        assert_eq!(code, 0, "{}: {out}{err}", s(v, "name"));
        let j: Value = serde_json::from_str(&out).unwrap();
        assert_eq!(j["transaction_hash"], v["expected"]["transaction_hash"], "{}", s(v, "name"));
        assert_eq!(j["unsigned_bytes"], v["expected"]["unsigned_bytes"], "{}", s(v, "name"));
        assert_eq!(j["payload"], v["expected"]["payload"], "{}", s(v, "name"));
    }
}

#[test]
fn cli_exit_codes() {
    for c in load("cli.json")["vectors"].as_array().unwrap() {
        let args: Vec<&str> = c["args"].as_array().unwrap().iter().map(|a| a.as_str().unwrap()).collect();
        let (code, out, err) = cli(&args, c["stdin"].as_str().unwrap_or(""), &[]);
        assert_eq!(code as i64, c["exit_code"].as_i64().unwrap(), "{}: {out}{err}", s(c, "case"));
        if let Some(class) = c["error_class"].as_str() {
            let j: Value = serde_json::from_str(&out).unwrap();
            assert_eq!(j["error_class"], class, "{}", s(c, "case"));
        }
    }
}

#[test]
fn cli_messages() {
    let d = load("messages.json");
    for v in d["vectors"].as_array().unwrap() {
        let hex_in = v["hex_input"].as_bool().unwrap();
        let msg = if hex_in { s(v, "message_hex") } else { s(v, "message") };
        let mut args = vec!["sign-message", v["seed"].as_str().unwrap(), &msg];
        if hex_in {
            args.push("--hex");
        }
        let (code, out, _) = cli(&args, "", &[]);
        let j: Value = serde_json::from_str(&out).unwrap();
        assert_eq!((code, j["signature"].as_str().unwrap()), (0, v["signature"].as_str().unwrap()));
        let mut args = vec!["verify-message", v["address"].as_str().unwrap(), &msg, v["signature"].as_str().unwrap()];
        if hex_in {
            args.push("--hex");
        }
        let (code, out, _) = cli(&args, "", &[]);
        let j: Value = serde_json::from_str(&out).unwrap();
        assert_eq!((code, j["valid"].as_bool().unwrap()), (0, true));
    }
    for n in d["invalid"].as_array().unwrap() {
        let (code, _, _) = cli(&["verify-message", n["address"].as_str().unwrap(), n["message"].as_str().unwrap(), n["signature"].as_str().unwrap()], "", &[]);
        assert_eq!(code as i64, n["exit_code"].as_i64().unwrap(), "{}", s(n, "case"));
    }
}

#[test]
fn cli_json_input_and_env_key() {
    let d = load("transactions.json");
    let v = &d["vectors"][0];
    let p = params_of(v);
    let stdin = serde_json::json!({"sender_privkey": s(v, "key"), "recipient": p["recipient"], "amount": p["amount"], "fee": v["fee"], "timestamp": v["timestamp"], "offline": true}).to_string();
    let (code, out, err) = cli(&["send-zbc", "--json-input", "--genesis", v["genesis"].as_str().unwrap()], &stdin, &[]);
    assert_eq!(code, 0, "{out}{err}");
    assert_eq!(serde_json::from_str::<Value>(&out).unwrap()["transaction_hash"], v["expected"]["transaction_hash"]);
    let ts = v["timestamp"].to_string();
    let key = s(v, "key");
    for args in [vec![p["recipient"].as_str(), p["amount"].as_str()], vec!["-", p["recipient"].as_str(), p["amount"].as_str()]] {
        let mut a = vec!["send-zbc"];
        a.extend(args);
        a.extend(["--timestamp", &ts, "--genesis", v["genesis"].as_str().unwrap(), "--offline"]);
        let (code, out, err) = cli(&a, "", &[("ZBC_KEY", &key)]);
        assert_eq!(code, 0, "{out}{err}");
        assert_eq!(serde_json::from_str::<Value>(&out).unwrap()["transaction_hash"], v["expected"]["transaction_hash"]);
    }
}

#[test]
fn cli_unreachable_node() {
    let d = load("transactions.json");
    let v = &d["vectors"][0];
    let p = params_of(v);
    let (code, out, _) = cli(&["send-zbc", v["key"].as_str().unwrap(), &p["recipient"], "1", "--api", "http://127.0.0.1:9", "--genesis", "v1", "--timeout", "2"], "", &[]);
    assert_eq!(code, 3, "{out}");
    assert_eq!(serde_json::from_str::<Value>(&out).unwrap()["error_class"], "node_unreachable");
}

#[test]
fn encryption() {
    let d = load("encryption.json");
    let unhex = |h: &str| hex::decode(h).unwrap();
    let key32 = |h: &str| -> [u8; 32] { unhex(h).try_into().unwrap() };
    for k in d["keys"].as_array().unwrap() {
        assert_eq!(hex::encode(ed25519_public_key_to_x25519(&unhex(&s(k, "public_key"))).unwrap()), s(k, "x25519_public_key"));
        assert_eq!(hex::encode(ed25519_seed_to_x25519(&unhex(&s(k, "seed")))), s(k, "x25519_secret_key"));
        assert_eq!(hex::encode(x25519_base(&key32(&s(k, "x25519_secret_key")))), s(k, "x25519_public_key"));
    }
    for v in d["sealed"].as_array().unwrap() {
        let f = seal(&unhex(&s(v, "plaintext_hex")), &unhex(&s(v, "recipient_public_key")), Some(&key32(&s(v, "ephemeral_secret_key")))).unwrap();
        assert_eq!(hex::encode(&f), s(v, "message_field"), "{}", s(v, "name"));
        assert_eq!(hex::encode(open_sealed(&f, &unhex(&s(v, "recipient_seed"))).unwrap()), s(v, "plaintext_hex"), "{}", s(v, "name"));
    }
    for v in d["samples"].as_array().unwrap() {
        assert_eq!(hex::encode(open_sealed(&unhex(&s(v, "message_field")), &unhex(&s(v, "recipient_seed"))).unwrap()), s(v, "plaintext_hex"), "{}", s(v, "name"));
    }
    for v in d["invalid"].as_array().unwrap() {
        if let Ok(f) = hex::decode(s(v, "message_field")) {
            assert!(open_sealed(&f, &unhex(&s(v, "recipient_seed"))).is_none(), "{}", s(v, "case"));
        }
    }
    let kp = KeyPair::from_hex(&s(&d["keys"][0], "seed")).unwrap();
    let f = seal(b"round trip", &kp.public_key, None).unwrap();
    assert_eq!(f.len(), 10 + SEALED_OVERHEAD);
    assert_eq!(open_sealed(&f, &kp.seed).unwrap(), b"round trip");
}

#[test]
fn cli_encrypt_and_decrypt() {
    let d = load("encryption.json");
    let seed = s(&d["keys"][0], "seed");
    let smp = &d["samples"][0];
    let (rc, out, err) = cli(&["send-zbc", &seed, &s(smp, "recipient_address"), "1", "--message", &s(smp, "plaintext"), "--encrypt", "--genesis", "v1", "--offline"], "", &[]);
    assert_eq!(rc, 0, "{out}{err}");
    let j: Value = serde_json::from_str(&out).unwrap();
    assert_eq!(s(&j, "message"), s(smp, "plaintext"));
    let field = s(&j["payload"], "message_hex");
    assert!(field.starts_with("5a424531") && field.len() == 2 * (s(smp, "plaintext").len() + 52));
    let (rc, out, err) = cli(&["decrypt-message", &s(smp, "recipient_seed"), &field], "", &[]);
    assert_eq!(rc, 0, "{out}{err}");
    assert_eq!(s(&serde_json::from_str::<Value>(&out).unwrap(), "message"), s(smp, "plaintext"));
    for v in d["samples"].as_array().unwrap() {
        let (rc, out, _) = cli(&["decrypt-message", &s(v, "recipient_seed"), &s(v, "message_field")], "", &[]);
        assert_eq!(rc, 0, "{}", s(v, "name"));
        assert_eq!(s(&serde_json::from_str::<Value>(&out).unwrap(), "message_hex"), s(v, "plaintext_hex"), "{}", s(v, "name"));
    }
    for v in d["invalid"].as_array().unwrap() {
        let (rc, out, _) = cli(&["decrypt-message", &s(v, "recipient_seed"), &s(v, "message_field")], "", &[]);
        assert_eq!(rc, v["exit_code"].as_i64().unwrap() as i32, "{}: {out}", s(v, "case"));
        assert_eq!(s(&serde_json::from_str::<Value>(&out).unwrap(), "error_class"), s(v, "error_class"), "{}", s(v, "case"));
    }
    let (rc, _, _) = cli(&["send-zbc", &seed, "0xd8dA6BF26964aF9D7eEd9e03E53415D37aA96045", "1", "--message", "x", "--encrypt", "--genesis", "v1", "--offline"], "", &[]);
    assert_eq!(rc, 2);
}
