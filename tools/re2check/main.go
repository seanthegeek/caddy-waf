// Command re2check reports which regular expressions Go's RE2 engine rejects.
//
// It exists so get_owasp_rules.py can validate translated OWASP CRS patterns
// against the same regexp package caddy-waf compiles rules with. Python's re
// module accepts backreferences, lookaround and other PCRE features that RE2
// does not, so a Python-side check would let rules through that then fail to
// load (see rules/README.md).
//
// Input:  a JSON array of {"id": "...", "pattern": "..."} objects on stdin.
// Output: a JSON object on stdout mapping each rejected id to the compile
// error. Patterns that compile are omitted, so an empty object means every
// pattern is loadable.
package main

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"regexp"
)

type entry struct {
	ID      string `json:"id"`
	Pattern string `json:"pattern"`
}

func main() {
	data, err := io.ReadAll(os.Stdin)
	if err != nil {
		fmt.Fprintln(os.Stderr, "re2check: read stdin:", err)
		os.Exit(2)
	}
	var entries []entry
	if err := json.Unmarshal(data, &entries); err != nil {
		fmt.Fprintln(os.Stderr, "re2check: parse input:", err)
		os.Exit(2)
	}
	failures := map[string]string{}
	for _, e := range entries {
		if _, err := regexp.Compile(e.Pattern); err != nil {
			failures[e.ID] = err.Error()
		}
	}
	out, err := json.Marshal(failures)
	if err != nil {
		fmt.Fprintln(os.Stderr, "re2check: encode output:", err)
		os.Exit(2)
	}
	fmt.Println(string(out))
}
