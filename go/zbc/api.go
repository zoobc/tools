// SPDX-License-Identifier: MIT
// Copyright (c) 2024-2026 ZooBC Foundation and Roberto Capodieci

package zbc

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// Client talks to one node or gateway over its HTTP API (spec/api.md).
type Client struct {
	API     string
	Timeout time.Duration
	HTTP    *http.Client
}

// NewClient makes a client for a base URL with a per-call timeout in seconds.
func NewClient(api string, timeoutSeconds int) *Client {
	return &Client{API: strings.TrimRight(api, "/"), Timeout: time.Duration(timeoutSeconds) * time.Second, HTTP: &http.Client{}}
}

// NodeInfo is the part of /api/v1/node/info the tools read.
type NodeInfo struct {
	SigningVersion int    `json:"signing_version"`
	GenesisHash    string `json:"genesis_hash"`
	Height         int64  `json:"height"`
	Version        string `json:"version"`
}

// Reply is one HTTP answer.
type Reply struct {
	Status int
	Text   string
	JSON   any // parsed body, or nil when not JSON
}

func (c *Client) call(method, path string, body []byte) (Reply, error) {
	ctx, cancel := context.WithTimeout(context.Background(), c.Timeout)
	defer cancel()
	var rd io.Reader
	if body != nil {
		rd = bytes.NewReader(body)
	}
	req, err := http.NewRequestWithContext(ctx, method, c.API+path, rd)
	if err != nil {
		return Reply{}, &ToolError{Code: ExitUsage, Message: "bad API URL: " + err.Error()}
	}
	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", "zbc-cli/1.0")
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	res, err := c.HTTP.Do(req)
	if err != nil {
		var ne net.Error
		if errors.Is(err, context.DeadlineExceeded) || (errors.As(err, &ne) && ne.Timeout()) {
			return Reply{}, &ToolError{Code: ExitTimeout, Message: fmt.Sprintf("Timed out: %s on %s", path, c.API)}
		}
		return Reply{}, &ToolError{Code: ExitNodeUnreachable, Message: fmt.Sprintf("Connection failed: %s on %s: %v", path, c.API, err)}
	}
	defer res.Body.Close()
	text, _ := io.ReadAll(res.Body)
	r := Reply{Status: res.StatusCode, Text: string(text)}
	var parsed any
	if json.Unmarshal(text, &parsed) == nil {
		r.JSON = parsed
	}
	return r, nil
}

// NodeInfo is GET /api/v1/node/info.
func (c *Client) NodeInfo() (NodeInfo, error) {
	r, err := c.call("GET", "/api/v1/node/info", nil)
	if err != nil {
		return NodeInfo{}, err
	}
	if r.Status != 200 {
		code := ExitNodeUnreachable
		if r.Status >= 500 {
			code = ExitNodeBusy
		}
		return NodeInfo{}, &ToolError{Code: code, Message: fmt.Sprintf("cannot read /api/v1/node/info from %s (HTTP %d) to learn which chain to sign for; pass --genesis <hex> to sign for a known chain", c.API, r.Status), Extra: map[string]any{"http_code": r.Status}}
	}
	var info NodeInfo
	_ = json.Unmarshal([]byte(r.Text), &info)
	return info, nil
}

// SigningRule is the chain's signing rule as the node reports it.
func (c *Client) SigningRule() (SigningContext, error) {
	info, err := c.NodeInfo()
	if err != nil {
		return SigningContext{}, err
	}
	if info.SigningVersion >= 2 {
		if !IsHex(info.GenesisHash, 64) {
			return SigningContext{}, Internal("node enforces chain-bound signing but reports no genesis hash; pass --genesis <hex>")
		}
		g, _ := hex.DecodeString(info.GenesisHash)
		return SigningContext{Version: 2, GenesisHash: g}, nil
	}
	return SigningContext{Version: 1}, nil
}

// Submit is POST /api/v1/transactions; accepted is true on 200/202. Transport failures are ToolErrors.
func (c *Client) Submit(p Payload) (reply Reply, accepted bool, err error) {
	body, _ := json.Marshal(p)
	r, err := c.call("POST", "/api/v1/transactions", body)
	if err != nil {
		return Reply{}, false, err
	}
	return r, r.Status == 200 || r.Status == 202, nil
}

// SubmitOrFail submits and returns a classified ToolError when the node rejects.
func (c *Client) SubmitOrFail(p Payload) (Reply, error) {
	r, ok, err := c.Submit(p)
	if err != nil {
		return r, err
	}
	if !ok {
		return r, RejectionError(r)
	}
	return r, nil
}

// RejectionError classifies a node's rejection reply (spec/api.md section 2).
func RejectionError(r Reply) *ToolError {
	text := r.Text
	if m, ok := r.JSON.(map[string]any); ok {
		if s, ok := m["error"].(string); ok {
			text = s
		}
	}
	var api any = r.Text
	if r.JSON != nil {
		api = r.JSON
	}
	return &ToolError{Code: ClassifyNodeError(r.Status, text), Message: text, Extra: map[string]any{"http_code": r.Status, "api_response": api}}
}

// Status is GET /api/v1/transactions/<hash>/status; a 404 answers status not_found rather than failing.
func (c *Client) Status(hash string) (map[string]any, error) {
	r, err := c.call("GET", "/api/v1/transactions/"+hash+"/status", nil)
	if err != nil {
		return nil, err
	}
	if r.Status != 200 && r.Status != 404 {
		return nil, RejectionError(r)
	}
	out := map[string]any{"transaction_hash": hash, "status": "unknown"}
	if r.Status == 404 {
		out["status"] = "not_found"
	}
	if m, ok := r.JSON.(map[string]any); ok {
		for k, v := range m {
			out[k] = v
		}
	}
	out["http_code"] = r.Status
	return out, nil
}

// Transaction is GET /api/v1/transactions/<hash>; exit 7 when unknown.
func (c *Client) Transaction(hash string) (map[string]any, error) {
	r, err := c.call("GET", "/api/v1/transactions/"+hash, nil)
	if err != nil {
		return nil, err
	}
	if r.Status != 200 {
		e := RejectionError(r)
		if r.Status == 404 {
			e.Code, e.Message = ExitNotFound, "Transaction not found"
		}
		return nil, e
	}
	m, _ := r.JSON.(map[string]any)
	return m, nil
}

// Account is GET /api/v1/accounts/<address>; exit 7 when unknown.
func (c *Client) Account(address string) (map[string]any, error) {
	r, err := c.call("GET", "/api/v1/accounts/"+url.PathEscape(address), nil)
	if err != nil {
		return nil, err
	}
	if r.Status != 200 {
		e := RejectionError(r)
		if r.Status == 404 {
			e.Code, e.Message = ExitNotFound, "Account not found"
		}
		return nil, e
	}
	m, _ := r.JSON.(map[string]any)
	return m, nil
}

// LatestBlock is GET /api/v1/blocks/latest: the reference block for a proof of ownership (`block_hash` or a gateway's `hash`).
func (c *Client) LatestBlock() (ReferenceBlock, error) {
	r, err := c.call("GET", "/api/v1/blocks/latest", nil)
	if err != nil {
		return ReferenceBlock{}, err
	}
	m, _ := r.JSON.(map[string]any)
	h, _ := m["block_hash"].(string)
	if h == "" {
		h, _ = m["hash"].(string)
	}
	if r.Status != 200 || !IsHex(h, 64) {
		return ReferenceBlock{}, &ToolError{Code: ExitInternal, Message: "Failed to fetch latest block from " + c.API, Extra: map[string]any{"http_code": r.Status}}
	}
	hb, _ := hex.DecodeString(h)
	height, _ := m["height"].(float64)
	return ReferenceBlock{Hash: hb, Height: uint32(height)}, nil
}
