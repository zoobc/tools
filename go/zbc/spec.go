// SPDX-License-Identifier: MIT
// Copyright (c) 2024-2026 ZooBC Foundation and Roberto Capodieci

package zbc

import "encoding/json"

// ParamDef is one command-line parameter of a transaction description (spec/transactions/README.md).
type ParamDef struct {
	Name     string `json:"name"`
	Kind     string `json:"kind"`
	Required bool   `json:"required"`
	Default  string `json:"default"`
	Help     string `json:"help"`
	Min      *int64 `json:"min"`
	Max      *int64 `json:"max"`
}

// FieldDef is one body field.
type FieldDef struct {
	Name        string `json:"name"`
	Encoding    string `json:"encoding"`
	From        string `json:"from"`
	Size        int    `json:"size"`
	Value       string `json:"value"`
	When        string `json:"when"`
	Computed    string `json:"computed"`
	DefaultFrom string `json:"default_from"`
	WhenZero    string `json:"when_zero"`
}

// TxDef is one transaction description.
type TxDef struct {
	Name        string            `json:"name"`
	Type        uint32            `json:"type"`
	Command     string            `json:"command"`
	Binary      string            `json:"binary"`
	Description string            `json:"description"`
	SenderKey   string            `json:"sender_key"`
	Recipient   string            `json:"recipient"`
	Options     []string          `json:"options"`
	NeedsNode   bool              `json:"needs_node"`
	Custom      string            `json:"custom"`
	Params      []ParamDef        `json:"params"`
	Body        []FieldDef        `json:"body"`
	Example     map[string]string `json:"example"`
	Notes       []string          `json:"notes"`
}

// Commands is every transaction description, in command order; CommandByName indexes it.
var (
	Commands      []TxDef
	CommandByName = map[string]*TxDef{}
)

func init() {
	if err := json.Unmarshal([]byte(commandsJSON), &Commands); err != nil {
		panic("commands_gen.go: " + err.Error())
	}
	for i := range Commands {
		CommandByName[Commands[i].Command] = &Commands[i]
	}
}
