// SPDX-License-Identifier: MIT
// Copyright (c) 2024-2026 ZooBC Foundation and Roberto Capodieci

package cli

import (
	"bufio"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/zoobc/tools/go/zbc"
)

const defaultFee = 5000000

var intRe = regexp.MustCompile(`^-?\d+$`)

var category = map[string]string{
	"send-zbc": "value", "liquid-payment": "value", "liquid-payment-stop": "value",
	"transfer-token": "tokens", "issue-token": "tokens", "mint-token": "tokens", "burn-token": "tokens", "finance-token": "tokens",
	"swap-create": "exchange", "swap-accept": "exchange", "swap-cancel": "exchange", "market-create": "exchange", "order-place": "exchange", "order-cancel": "exchange",
	"app-create": "apps", "app-join": "apps", "app-move": "apps", "app-resign": "apps", "app-claim": "apps", "app-settle": "apps",
	"store-file": "storage", "add-prepaid-storage": "storage", "dfs-create-file": "storage",
	"register-node": "node", "update-node": "node", "remove-node": "node", "claim-node": "node", "governance-vote": "node",
	"register-gateway": "gateway", "unregister-gateway": "gateway", "gateway-heartbeat": "gateway", "archival-register": "gateway",
	"archival-unregister": "gateway", "relay-register": "gateway", "relay-unregister": "gateway",
	"register-release": "governance", "revoke-release": "governance", "release-authority-propose": "governance", "release-authority-accept": "governance",
	"sign-message": "keys", "verify-message": "keys", "decrypt-message": "keys",
}

var messageCommands = map[string]struct {
	desc   string
	params []zbc.ParamDef
}{
	"sign-message": {"Sign a message with a private key (ZBC-MSG-v1, off-chain, no node needed)", []zbc.ParamDef{
		{Name: "sender_privkey", Kind: "privkey", Required: true, Help: "Sender private key (64 hex)"},
		{Name: "message", Kind: "string", Required: true, Help: "text to sign (hex bytes with --hex)"}}},
	"verify-message": {"Verify a ZBC-MSG-v1 message signature against a ZBC_ address (off-chain)", []zbc.ParamDef{
		{Name: "address", Kind: "string", Required: true, Help: "signer's ZBC_ address (or 64-hex public key)"},
		{Name: "message", Kind: "string", Required: true, Help: "the signed text (hex bytes with --hex)"},
		{Name: "signature", Kind: "string", Required: true, Help: "64-byte Ed25519 signature, 128 hex"}}},
	"decrypt-message": {"Decrypt a transaction message sealed with --encrypt, with the recipient's private key (off-chain)", []zbc.ParamDef{
		{Name: "sender_privkey", Kind: "privkey", Required: true, Help: "the recipient's private key (64 hex); '-' or omitted = ZBC_KEY"},
		{Name: "message_hex", Kind: "string", Required: true, Help: "the transaction's message field as hex: ZBE1 then the sealed box"}}},
}

type options struct {
	api        string
	fee        int64
	timeout    int
	genesis    string
	jsonInput  bool
	verbose    bool
	message    *string
	encrypt    bool
	chain      string
	escrow     *zbc.Escrow
	hex        bool
	offline    bool
	timestamp  *int64
	token      *string
	help       bool
	escrowSeen map[string]bool
}

type env struct {
	stdin  io.Reader
	stdout io.Writer
	stderr io.Writer
	getenv func(string) string
	isTTY  bool
}

func (e *env) out(v any) {
	b, _ := json.MarshalIndent(v, "", "  ")
	fmt.Fprintln(e.stdout, string(b))
}

func (e *env) emitError(err *zbc.ToolError, verbose bool) int {
	if verbose {
		fmt.Fprintln(e.stderr, "Error: "+err.Message)
	} else {
		e.out(err.JSON())
	}
	return err.Code
}

func parseArgs(argv []string, e *env) ([]string, *options, error) {
	o := &options{api: "http://localhost:8080", fee: defaultFee, timeout: 20, escrowSeen: map[string]bool{}}
	if v := e.getenv("ZBC_API"); v != "" {
		o.api = v
	}
	if v := e.getenv("ZBC_TIMEOUT"); intRe.MatchString(v) {
		if n, _ := strconv.Atoi(v); n > 0 {
			o.timeout = n
		}
	}
	var positional []string
	escrow := zbc.Escrow{}
	for i := 0; i < len(argv); i++ {
		a := argv[i]
		need := func(what string) (string, error) {
			if i+1 >= len(argv) {
				return "", zbc.Usage("%s requires a value%s", a, what)
			}
			i++
			return argv[i], nil
		}
		integer := func(s, what string) (int64, error) {
			if !intRe.MatchString(s) {
				return 0, zbc.Usage("%s", what)
			}
			n, err := strconv.ParseInt(s, 10, 64)
			if err != nil {
				return 0, zbc.Usage("%s", what)
			}
			return n, nil
		}
		var v string
		var err error
		switch a {
		case "-v", "--verbose":
			o.verbose = true
		case "--json":
			o.verbose = false
		case "--json-input":
			o.jsonInput = true
		case "--encrypt":
			o.encrypt = true
		case "--hex":
			o.hex = true
		case "--offline":
			o.offline = true
		case "-h", "--help":
			o.help = true
		case "--message":
			if v, err = need(""); err != nil {
				return nil, nil, err
			}
			o.message = &v
		case "--fee":
			if v, err = need(""); err != nil {
				return nil, nil, err
			}
			if o.fee, err = integer(v, "--fee must be a whole number of atomic units"); err != nil {
				return nil, nil, err
			}
		case "--api":
			if o.api, err = need(""); err != nil {
				return nil, nil, err
			}
		case "--timeout", "--timeout-seconds":
			if v, err = need(" (seconds)"); err != nil {
				return nil, nil, err
			}
			n, convErr := strconv.Atoi(v)
			if convErr != nil || !regexp.MustCompile(`^\d+$`).MatchString(v) {
				return nil, nil, zbc.Usage("%s must be a whole number of seconds", a)
			}
			if n <= 0 {
				return nil, nil, zbc.Usage("%s must be > 0", a)
			}
			o.timeout = n
		case "--genesis":
			if o.genesis, err = need(""); err != nil {
				return nil, nil, err
			}
		case "--chain":
			if o.chain, err = need(""); err != nil {
				return nil, nil, err
			}
		case "--token":
			if v, err = need(""); err != nil {
				return nil, nil, err
			}
			o.token = &v
		case "--timestamp":
			if v, err = need(" (Unix seconds)"); err != nil {
				return nil, nil, err
			}
			n, err := integer(v, "--timestamp must be a whole number of Unix seconds")
			if err != nil {
				return nil, nil, err
			}
			if n <= 0 {
				return nil, nil, zbc.Usage("--timestamp must be > 0")
			}
			o.timestamp = &n
		case "--escrow-approver":
			if escrow.Approver, err = need(""); err != nil {
				return nil, nil, err
			}
			o.escrowSeen["approver"] = true
		case "--escrow-commission":
			if v, err = need(""); err != nil {
				return nil, nil, err
			}
			if escrow.Commission, err = integer(v, "--escrow-commission must be a whole number of atomic units"); err != nil {
				return nil, nil, err
			}
			o.escrowSeen["commission"] = true
		case "--escrow-timeout":
			if v, err = need(""); err != nil {
				return nil, nil, err
			}
			if escrow.Timeout, err = integer(v, "--escrow-timeout must be a Unix timestamp in seconds"); err != nil {
				return nil, nil, err
			}
			o.escrowSeen["timeout"] = true
		case "--escrow-instruction":
			if escrow.Instruction, err = need(""); err != nil {
				return nil, nil, err
			}
			o.escrowSeen["instruction"] = true
		default:
			if len(a) > 1 && a[0] == '-' && !(a[1] >= '0' && a[1] <= '9') && a[1] != '.' {
				return nil, nil, zbc.Usage("Unknown option: %s", a)
			}
			positional = append(positional, a)
		}
	}
	if o.offline && o.genesis == "" && e.getenv("ZOOBC_GENESIS_HASH") == "" {
		return nil, nil, zbc.Usage("--offline needs --genesis <hex|v1> (or ZOOBC_GENESIS_HASH): nothing is asked of a node")
	}
	if len(o.escrowSeen) > 0 {
		if err := checkEscrow(&escrow); err != nil {
			return nil, nil, err
		}
		o.escrow = &escrow
	}
	return positional, o, nil
}

func checkEscrow(e *zbc.Escrow) error {
	if e.Approver == "" {
		return zbc.Usage("Escrow requires --escrow-approver")
	}
	if e.Timeout <= 0 {
		return zbc.Usage("Escrow requires --escrow-timeout > 0")
	}
	if e.Commission < 0 {
		return zbc.Usage("Escrow commission cannot be negative")
	}
	return nil
}

func isPlaceholder(s string) bool { return s == "-" || s == "@env" || s == "env:ZBC_KEY" }

func resolveParams(params []zbc.ParamDef, positional []string, o *options, e *env) (map[string]string, error) {
	values := map[string]string{}
	keyIsFirst := len(params) > 0 && params[0].Name == "sender_privkey"
	envKey := ""
	if keyIsFirst {
		envKey = e.getenv("ZBC_KEY")
	}
	if o.jsonInput {
		raw, _ := io.ReadAll(e.stdin)
		text := strings.TrimSpace(string(raw))
		if text == "" {
			return nil, zbc.Usage("No JSON input received on stdin")
		}
		var j map[string]any
		if err := json.Unmarshal([]byte(text), &j); err != nil || j == nil {
			return nil, zbc.Usage("Invalid JSON input")
		}
		for _, p := range params {
			if v, ok := j[p.Name]; ok {
				if s, ok := v.(string); ok {
					values[p.Name] = s
				} else {
					b, _ := json.Marshal(v)
					values[p.Name] = string(b)
				}
			} else if p.Default != "" {
				values[p.Name] = p.Default
			} else if p.Name == "sender_privkey" && envKey != "" {
				values[p.Name] = envKey
			} else if p.Required {
				return nil, zbc.Usage("Missing required field: %s", p.Name)
			}
			if keyIsFirst && p.Name == "sender_privkey" && isPlaceholder(values[p.Name]) {
				if envKey == "" {
					return nil, zbc.Usage("sender_privkey is '-' but ZBC_KEY is not set")
				}
				values[p.Name] = envKey
			}
		}
		num := func(k, what string) (*int64, error) {
			v, ok := j[k]
			if !ok {
				return nil, nil
			}
			var s string
			switch t := v.(type) {
			case float64:
				s = strconv.FormatFloat(t, 'f', -1, 64)
			case json.Number:
				s = t.String()
			case string:
				s = t
			}
			if !intRe.MatchString(s) {
				return nil, zbc.Usage("%s must be a whole number", what)
			}
			n, _ := strconv.ParseInt(s, 10, 64)
			return &n, nil
		}
		if n, err := num("fee", "fee"); err != nil {
			return nil, err
		} else if n != nil {
			o.fee = *n
		}
		if n, err := num("timeout_seconds", "timeout_seconds"); err != nil {
			return nil, err
		} else if n != nil {
			if *n <= 0 {
				return nil, zbc.Usage("timeout_seconds must be > 0")
			}
			o.timeout = int(*n)
		}
		if n, err := num("timestamp", "timestamp"); err != nil {
			return nil, err
		} else if n != nil {
			if *n <= 0 {
				return nil, zbc.Usage("timestamp must be > 0")
			}
			o.timestamp = n
		}
		if b, ok := j["offline"].(bool); ok {
			o.offline = b
		}
		if s, ok := j["api_url"].(string); ok {
			o.api = s
		}
		if s, ok := j["message"].(string); ok {
			o.message = &s
		}
		if b, ok := j["hex"].(bool); ok {
			o.hex = b
		}
		if b, ok := j["verbose"].(bool); ok && b {
			o.verbose = true
		}
		if em, ok := j["escrow"].(map[string]any); ok {
			esc := zbc.Escrow{}
			if s, ok := em["approver"].(string); ok {
				esc.Approver = s
			}
			if f, ok := em["commission"].(float64); ok {
				esc.Commission = int64(f)
			}
			if f, ok := em["timeout"].(float64); ok {
				esc.Timeout = int64(f)
			}
			if s, ok := em["instruction"].(string); ok {
				esc.Instruction = s
			}
			if err := checkEscrow(&esc); err != nil {
				return nil, err
			}
			o.escrow = &esc
		}
		if o.offline && o.genesis == "" && e.getenv("ZOOBC_GENESIS_HASH") == "" {
			return nil, zbc.Usage("--offline needs --genesis <hex|v1> (or ZOOBC_GENESIS_HASH): nothing is asked of a node")
		}
		return values, nil
	}
	if len(positional) == 0 && e.isTTY && o.verbose {
		rd := bufio.NewReader(e.stdin)
		for _, p := range params {
			def := ""
			if p.Default != "" {
				def = " [" + p.Default + "]"
			}
			fmt.Fprintf(e.stdout, "  %s%s: ", p.Help, def)
			line, _ := rd.ReadString('\n')
			v := strings.TrimSpace(line)
			if v == "" {
				v = p.Default
			}
			if p.Name == "sender_privkey" && (v == "" || isPlaceholder(v)) {
				v = envKey
			}
			if p.Required && v == "" {
				return nil, zbc.Usage("Missing required argument: %s", p.Name)
			}
			values[p.Name] = v
		}
		return values, nil
	}
	pos := append([]string{}, positional...)
	if keyIsFirst {
		required := 0
		for _, p := range params {
			if p.Required && p.Default == "" {
				required++
			}
		}
		if len(pos) > 0 && isPlaceholder(pos[0]) {
			if envKey == "" {
				return nil, zbc.Usage("key argument is '-' but ZBC_KEY is not set")
			}
			pos[0] = envKey
		} else if envKey != "" && len(pos)+1 == required {
			pos = append([]string{envKey}, pos...)
		}
	}
	for i, p := range params {
		switch {
		case i < len(pos):
			values[p.Name] = pos[i]
		case p.Default != "":
			values[p.Name] = p.Default
		case p.Required:
			hint := ""
			if i == 0 && keyIsFirst {
				hint = " (pass it, or set ZBC_KEY)"
			}
			return nil, zbc.Usage("Missing required argument: %s%s", p.Name, hint)
		default:
			values[p.Name] = ""
		}
	}
	if len(pos) > len(params) {
		feeArg := pos[len(params)]
		if !intRe.MatchString(feeArg) {
			return nil, zbc.Usage("Fee must be a whole number of atomic units, got \"%s\". The API endpoint is passed with --api URL, not as a positional argument.", feeArg)
		}
		o.fee, _ = strconv.ParseInt(feeArg, 10, 64)
	}
	if len(pos) > len(params)+1 {
		o.api = pos[len(params)+1]
	}
	return values, nil
}

func commandOf(cmd string) (desc string, params []zbc.ParamDef, txType uint32, ok bool) {
	if m, ok := messageCommands[cmd]; ok {
		return m.desc, m.params, 0, true
	}
	if d, ok := zbc.CommandByName[cmd]; ok {
		return d.Description, d.Params, d.Type, true
	}
	return "", nil, 0, false
}

func printList(e *env) {
	type entry struct{ cmd, desc string }
	var all []entry
	for _, c := range zbc.Commands {
		all = append(all, entry{c.Command, c.Description})
	}
	for k, v := range messageCommands {
		all = append(all, entry{k, v.desc})
	}
	sort.Slice(all, func(i, j int) bool { return all[i].cmd < all[j].cmd })
	groups := map[string][]string{}
	for _, x := range all {
		g := category[x.cmd]
		if g == "" {
			g = "other"
		}
		groups[g] = append(groups[g], fmt.Sprintf("  %-26s%s", x.cmd, x.desc))
	}
	fmt.Fprintf(e.stdout, "ZooBC unified transaction CLI — %d commands.\n  Default: JSON in, JSON out.   --verbose: prompt each field + text output.\n"+
		"  echo '{...}' | zbc-cli <cmd> --json-input     zbc-cli help <cmd>  (fields for one tx)\n\n", len(all))
	for _, g := range []string{"value", "tokens", "exchange", "apps", "storage", "account", "node", "gateway", "governance", "keys", "other"} {
		if lines, ok := groups[g]; ok {
			fmt.Fprintf(e.stdout, "[%s]\n%s\n\n", g, strings.Join(lines, "\n"))
		}
	}
	fmt.Fprint(e.stdout, "First param is the sender private key (or set ZBC_KEY and omit it / pass '-'); verify-message takes an address.\n"+
		"`zbc-cli help <cmd>` shows a command's JSON fields; `zbc-cli <cmd> --help` the options, env vars and exit codes.\n")
}

func printHelp(cmd string, e *env) int {
	desc, params, txType, ok := commandOf(cmd)
	if !ok {
		fmt.Fprintf(e.stderr, "Unknown command: %s (try `zbc-cli list`)\n", cmd)
		return zbc.ExitUsage
	}
	fmt.Fprintf(e.stdout, "%s — %s  (tx type %d)\nJSON fields (default: JSON in/out; --json-input reads them on stdin; positional order matches):\n", cmd, desc, txType)
	sample := map[string]string{}
	for _, p := range params {
		req := "(optional) "
		if p.Required {
			req = "(required) "
		}
		def := ""
		if p.Default != "" {
			def = "  [default: " + p.Default + "]"
		}
		fmt.Fprintf(e.stdout, "  %-18s%s%s%s\n", p.Name, req, p.Help, def)
		if p.Default != "" {
			sample[p.Name] = p.Default
		} else {
			sample[p.Name] = "..."
		}
	}
	b, _ := json.Marshal(sample)
	fmt.Fprintf(e.stdout, "Sample: %s\nRun with --verbose to be prompted for each field and get human-readable output.\n", b)
	return 0
}

const usageText = `Options:
  -v, --verbose         Verbose output (default is JSON)
  --json-input          Read parameters from JSON on stdin
  --chain <name>        Read the recipient as this chain: zbc, btc, eth, sol, dot, ada, xrp, trx, xtz
  --message <text>      Optional transaction message
  --encrypt             Encrypt --message to the recipient (ZBC only)
  --genesis <hex|v1>    Sign for this chain (its genesis block hash) without asking the node; 'v1' = legacy unbound digest. Default: ask --api.
  --escrow-approver <addr>   Escrow approver address
  --escrow-commission <n>    Escrow commission (atomic units)
  --escrow-timeout <n>       Escrow timeout as a FUTURE Unix timestamp (seconds)
  --escrow-instruction <s>   Escrow instruction
  --fee <n>             Transaction fee (default: 5000000 = 0.05 ZBC)
  --api <url>           API endpoint (default: $ZBC_API, else http://localhost:8080)
  --timeout <s>         Bound for each HTTP call, seconds (default: $ZBC_TIMEOUT, else 20; also --timeout-seconds)
  --hex                 sign-message/verify-message: the message is hex bytes, not text
  --offline             Build, sign and hash, print unsigned_bytes, digest, signature, transaction_bytes and transaction_hash, exit 0 without submitting. Needs --genesis.
  --timestamp <n>       Transaction timestamp, Unix seconds (default: now)

Environment:
  ZBC_KEY               Sender private key (64 hex), used when the key argument is omitted or '-'
  ZBC_API, ZBC_TIMEOUT  Defaults for --api and --timeout
  ZOOBC_GENESIS_HASH    Default for --genesis

Exit codes:
  0 ok  1 internal  2 usage  3 node unreachable  4 insufficient balance  5 fee too low
  6 rejected by node  7 not found  8 timeout  9 node busy (5xx)  10 signature invalid
  JSON errors carry the same code as "exit_code" and its name as "error_class".
`

func printUsage(cmd string, params []zbc.ParamDef, e *env) {
	var args, list strings.Builder
	for _, p := range params {
		if p.Required {
			args.WriteString(" <" + p.Name + ">")
		} else {
			args.WriteString(" [" + p.Name + "]")
		}
		list.WriteString(fmt.Sprintf("  %-22s%s\n", p.Name, p.Help))
	}
	fmt.Fprintf(e.stdout, "zbc-cli %s\n\nUsage:\n  zbc-cli %s [options]%s [fee] [api_url]\n\n%s\nParameters:\n%s", cmd, cmd, args.String(), usageText, list.String())
}

func messageBytes(text string, hexIn bool) ([]byte, error) {
	if !hexIn {
		return []byte(text), nil
	}
	if !zbc.IsHex(text, 0) {
		return nil, zbc.Usage("--hex message is not valid hex")
	}
	b, _ := hex.DecodeString(text)
	return b, nil
}

func runSignMessage(v map[string]string, o *options, e *env) (int, error) {
	kp, err := zbc.KeyPairFromHex(v["sender_privkey"])
	if err != nil {
		return 0, zbc.Usage("Private key must be 64 hex characters (32 bytes)")
	}
	msg, err := messageBytes(v["message"], o.hex)
	if err != nil {
		return 0, err
	}
	s := zbc.SignMessage(kp, msg)
	if o.verbose {
		fmt.Fprintf(e.stdout, "Address:   %s\nDigest:    %s\nSignature: %s\n", s.Address, s.Digest, s.Signature)
		return 0, nil
	}
	out := map[string]any{"success": true, "scheme": s.Scheme, "address": s.Address, "public_key": s.PublicKey, "message_hex": s.MessageHex, "digest": s.Digest, "signature": s.Signature}
	if !o.hex {
		out["message"] = v["message"]
	}
	e.out(out)
	return 0, nil
}

func runDecryptMessage(v map[string]string, o *options, e *env) (int, error) {
	kp, err := zbc.KeyPairFromHex(v["sender_privkey"])
	if err != nil {
		return 0, zbc.Usage("Private key must be 64 hex characters (32 bytes)")
	}
	if !zbc.IsHex(v["message_hex"], 0) {
		return 0, zbc.Usage("message_hex must be hex")
	}
	field, _ := hex.DecodeString(v["message_hex"])
	if !zbc.IsSealed(field) {
		return 0, zbc.Usage("message is not encrypted (no ZBE1 prefix)")
	}
	plaintext, ok := zbc.OpenSealed(field, kp.Seed)
	if !ok {
		return 0, &zbc.ToolError{Code: zbc.ExitVerifyFailed, Message: "decryption failed: the key does not open this message, or it is corrupted"}
	}
	if o.verbose {
		fmt.Fprintf(e.stdout, "%s\n", plaintext)
		return 0, nil
	}
	e.out(map[string]any{"success": true, "recipient": kp.Address(), "message": string(plaintext), "message_hex": hex.EncodeToString(plaintext)})
	return 0, nil
}

func runVerifyMessage(v map[string]string, o *options, e *env) (int, error) {
	pub := zbc.PublicKeyOfAddress(v["address"])
	if pub == nil {
		return 0, zbc.Usage("address must be a ZBC_ account (Ed25519) address")
	}
	msg, err := messageBytes(v["message"], o.hex)
	if err != nil {
		return 0, err
	}
	if !zbc.IsHex(v["signature"], 0) {
		return 0, zbc.Usage("signature must be hex")
	}
	if len(v["signature"]) != 128 {
		return 0, zbc.Usage("signature must be 64 bytes (128 hex characters)")
	}
	sig, _ := hex.DecodeString(v["signature"])
	valid := zbc.VerifyMessage(v["address"], msg, sig)
	address := zbc.MustEncodeZbcAddress(pub, "ZBC")
	code := zbc.ExitOK
	if !valid {
		code = zbc.ExitVerifyFailed
	}
	if o.verbose {
		word := "VALID"
		if !valid {
			word = "INVALID"
		}
		fmt.Fprintf(e.stdout, "%s signature for %s\n", word, address)
		return code, nil
	}
	e.out(map[string]any{"success": true, "valid": valid, "scheme": zbc.MessageSigningScheme, "address": address,
		"digest": hex.EncodeToString(zbc.MessageDigest(msg)), "exit_code": code, "error_class": zbc.ErrorClass(code)})
	return code, nil
}

func signingContext(o *options, c *zbc.Client, e *env) (zbc.SigningContext, error) {
	g := o.genesis
	if g == "" {
		g = e.getenv("ZOOBC_GENESIS_HASH")
	}
	if g != "" {
		ctx, err := zbc.SigningContextOf(g)
		if err != nil {
			return ctx, zbc.Usage("%v", err)
		}
		return ctx, nil
	}
	ctx, err := c.SigningRule()
	if te, ok := err.(*zbc.ToolError); ok && (te.Code == zbc.ExitNodeUnreachable || te.Code == zbc.ExitTimeout) {
		verb := "cannot read"
		if te.Code == zbc.ExitTimeout {
			verb = "timed out reading"
		}
		return ctx, &zbc.ToolError{Code: te.Code, Message: fmt.Sprintf("%s /api/v1/node/info from %s to learn which chain to sign for; pass --genesis <hex> to sign for a known chain", verb, o.api)}
	}
	return ctx, err
}

func runTransaction(def *zbc.TxDef, v map[string]string, o *options, e *env) (int, error) {
	for _, p := range def.Params {
		if v[p.Name] != "" || p.Required {
			val, err := zbc.ValidateParam(p, v[p.Name])
			if err != nil {
				return 0, err
			}
			v[p.Name] = val
		}
	}
	sender, err := zbc.KeyPairFromHex(v[def.SenderKey])
	if err != nil {
		return 0, zbc.Usage("%v", err)
	}
	client := zbc.NewClient(o.api, o.timeout)
	ctx, err := signingContext(o, client, e)
	if err != nil {
		return 0, err
	}
	timestamp := time.Now().Unix()
	if o.timestamp != nil {
		timestamp = *o.timestamp
	}
	var recipient []byte
	extra := map[string]any{}
	if def.Recipient == "required" {
		r, err := zbc.ParseAddress(v["recipient"], o.chain)
		if err != nil {
			return 0, zbc.Usage("invalid recipient address: %v", err)
		}
		recipient = r.Bytes()
		extra["recipient"], extra["recipient_type"] = r.Display, r.TypeName()
	}
	if o.token != nil {
		if def.Command != "liquid-payment" {
			return 0, zbc.Usage("--token applies to liquid-payment only")
		}
		v["token_id"] = *o.token
	}
	files := map[string][]byte{}
	for _, p := range def.Params {
		if p.Kind == "file" {
			b, err := os.ReadFile(v[p.Name])
			if err != nil {
				return 0, zbc.Usage("cannot read %s: %s", p.Name, v[p.Name])
			}
			files[p.Name] = b
		}
	}
	in := zbc.CustomInput{Def: def, Params: v, Sender: sender, Ctx: ctx, Timestamp: timestamp}
	if def.NeedsNode {
		block, err := client.LatestBlock()
		if err != nil {
			return 0, err
		}
		in.Block = &block
	}
	var body []byte
	if def.Custom == "multisig" || def.Custom == "settle" {
		b, more, err := zbc.CustomBody(in)
		if err != nil {
			return 0, err
		}
		body = b
		for k, val := range more {
			extra[k] = val
		}
	} else {
		bc := &zbc.BodyContext{Sender: sender, Files: files, Computed: map[string][]byte{}}
		more, err := zbc.ComputeFields(in, bc)
		if err != nil {
			return 0, err
		}
		for k, val := range more {
			extra[k] = val
		}
		if body, err = zbc.BuildBody(def, v, bc); err != nil {
			return 0, err
		}
	}
	for _, p := range def.Params {
		if p.Kind == "privkey" || p.Kind == "file" || p.Name == "recipient" {
			continue
		}
		if _, done := extra[p.Name]; done {
			continue
		}
		val := v[p.Name]
		if (p.Kind == "int64" || p.Kind == "uint64" || p.Kind == "uint32" || p.Kind == "uint8") && intRe.MatchString(val) {
			n, _ := strconv.ParseInt(val, 10, 64)
			extra[p.Name] = n
		} else {
			extra[p.Name] = val
		}
	}
	if def.Command == "approve-escrow" {
		h, _ := hex.DecodeString(v["transaction_hash"])
		extra["escrowed_transaction_hash"] = v["transaction_hash"]
		extra["transaction_id"] = zbc.TransactionID(h)
		delete(extra, "transaction_hash")
	}
	extra["sender"] = sender.Address()
	var msg []byte
	if o.message != nil {
		msg = []byte(*o.message)
	}
	if o.encrypt && len(msg) > 0 { // --encrypt: seal the message to the recipient's key (signing.md 8)
		if len(recipient) != 36 {
			return 0, zbc.Usage("--encrypt is only supported for ZBC recipients")
		}
		if msg, err = zbc.Seal(msg, recipient[4:], nil); err != nil {
			return 0, err
		}
	}
	signed, err := zbc.SignTransaction(zbc.Unsigned{Type: def.Type, Timestamp: timestamp, Sender: sender.AccountBytes(), Recipient: recipient,
		Fee: o.fee, Body: body, Escrow: o.escrow, Message: msg}, sender, ctx)
	if err != nil {
		return 0, zbc.Usage("Invalid escrow approver: %v", err)
	}
	fields := map[string]any{"transaction_hash": hex.EncodeToString(signed.Hash), "transaction_type": def.Type,
		"sender_account_address": signed.Payload.SenderAccountAddress, "recipient_account_address": signed.Payload.RecipientAccountAddress,
		"fee": o.fee, "timestamp": timestamp}
	common := map[string]any{}
	if o.message != nil && *o.message != "" {
		common["message"] = *o.message
	}
	if signed.Payload.Escrow != nil {
		common["escrow"] = signed.Payload.Escrow
	}
	for k, val := range extra {
		common[k] = val
	}
	if o.offline {
		if o.verbose {
			g := ""
			if signed.GenesisHash != nil {
				g = " (genesis " + hex.EncodeToString(signed.GenesisHash) + ")"
			}
			pl, _ := json.Marshal(signed.Payload)
			fmt.Fprintf(e.stdout, "OFFLINE: transaction built and signed, not submitted\n\nTransaction hash:  %s\nSigning version:   %d%s\nTimestamp:         %d\n"+
				"Unsigned bytes:    %s\nDigest:            %s\nSignature:         %s\nTransaction bytes: %s\nPayload:           %s\n",
				fields["transaction_hash"], signed.SigningVersion, g, timestamp, hex.EncodeToString(signed.Unsigned), hex.EncodeToString(signed.Digest),
				hex.EncodeToString(signed.Signature), hex.EncodeToString(signed.Bytes), pl)
			return 0, nil
		}
		out := map[string]any{"success": true, "offline": true, "signing_version": signed.SigningVersion, "unsigned_bytes": hex.EncodeToString(signed.Unsigned),
			"digest": hex.EncodeToString(signed.Digest), "signature": hex.EncodeToString(signed.Signature), "transaction_bytes": hex.EncodeToString(signed.Bytes),
			"payload": signed.Payload}
		if signed.GenesisHash != nil {
			out["genesis_hash"] = hex.EncodeToString(signed.GenesisHash)
		}
		for k, val := range fields {
			out[k] = val
		}
		for k, val := range common {
			out[k] = val
		}
		e.out(out)
		return 0, nil
	}
	r, accepted, err := client.Submit(signed.Payload)
	if err != nil {
		return 0, err
	}
	if !accepted {
		te := zbc.RejectionError(r)
		if o.verbose {
			fmt.Fprintf(e.stderr, "FAILED: Transaction submission rejected (%s)\nHTTP %d: %s\n", zbc.ErrorClass(te.Code), r.Status, r.Text)
		} else {
			e.out(te.JSON())
		}
		return te.Code, nil
	}
	if o.verbose {
		fmt.Fprintf(e.stdout, "SUCCESS: %s submitted!\n\nTransaction Hash: %s\n", def.Command, fields["transaction_hash"])
		return 0, nil
	}
	out := map[string]any{"success": true, "api_response": r.JSON}
	if r.JSON == nil {
		out["api_response"] = r.Text
	}
	for k, val := range fields {
		out[k] = val
	}
	for k, val := range common {
		out[k] = val
	}
	e.out(out)
	return 0, nil
}

// Run is zbc-cli: args without the program name. Returns the exit code.
func Run(args []string, stdin io.Reader, stdout, stderr io.Writer) int {
	e := &env{stdin: stdin, stdout: stdout, stderr: stderr, getenv: os.Getenv}
	if f, ok := stdin.(*os.File); ok {
		if st, err := f.Stat(); err == nil {
			e.isTTY = st.Mode()&os.ModeCharDevice != 0
		}
	}
	if len(args) == 0 {
		fmt.Fprint(stdout, "ZooBC unified transaction CLI\nUsage: zbc-cli <command> <params...> [--api URL] [--fee N] [--timeout S] [--verbose] [--json-input]\n"+
			"       zbc-cli list   (show all commands)      zbc-cli <command> --help  (options, env vars, exit codes)\n")
		return zbc.ExitUsage
	}
	cmd := args[0]
	if cmd == "help" && len(args) >= 2 {
		return printHelp(args[1], e)
	}
	if cmd == "list" || cmd == "--help" || cmd == "-h" || cmd == "help" {
		printList(e)
		return 0
	}
	if _, _, _, ok := commandOf(cmd); !ok {
		fmt.Fprintf(stderr, "Unknown command: %s (try `zbc-cli list`)\n", cmd)
		return zbc.ExitUsage
	}
	return RunTool(cmd, args[1:], stdin, stdout, stderr)
}

// RunTool runs one command with its own arguments (the per-tool programs and Run share it).
func RunTool(cmd string, args []string, stdin io.Reader, stdout, stderr io.Writer) int {
	e := &env{stdin: stdin, stdout: stdout, stderr: stderr, getenv: os.Getenv}
	if f, ok := stdin.(*os.File); ok {
		if st, err := f.Stat(); err == nil {
			e.isTTY = st.Mode()&os.ModeCharDevice != 0
		}
	}
	_, params, _, ok := commandOf(cmd)
	if !ok {
		fmt.Fprintf(stderr, "Unknown command: %s (try `zbc-cli list`)\n", cmd)
		return zbc.ExitUsage
	}
	verbose := false
	code, err := func() (int, error) {
		positional, o, err := parseArgs(args, e)
		if err != nil {
			return 0, err
		}
		verbose = o.verbose
		if o.help {
			printUsage(cmd, params, e)
			return 0, nil
		}
		values, err := resolveParams(params, positional, o, e)
		if err != nil {
			return 0, err
		}
		verbose = o.verbose
		switch cmd {
		case "sign-message":
			return runSignMessage(values, o, e)
		case "verify-message":
			return runVerifyMessage(values, o, e)
		case "decrypt-message":
			return runDecryptMessage(values, o, e)
		}
		return runTransaction(zbc.CommandByName[cmd], values, o, e)
	}()
	if err != nil {
		if te, ok := err.(*zbc.ToolError); ok {
			return e.emitError(te, verbose)
		}
		return e.emitError(zbc.Internal("%v", err), verbose)
	}
	return code
}
