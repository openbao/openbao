package server

import (
	"strings"
	"testing"
)

// The JSON form of the initialize stanza, as documented on the
// self-initialization page, must parse cleanly: hcl v1's JSON parser
// flattens nested objects so that the stanza's key and the outer block's
// name fuse into one item (e.g. [initialize audit]), which historically
// caused the block's name to be reported as an unknown field of the
// configuration when the stanza appeared as the first JSON key. The
// request names within the stanza were similarly reported as unknown
// fields of the outer block (covered by profiles-level tests).
const selfInitJSONInitializeFirst = `{
	"initialize": [
		{
			"audit": {
				"request": [
					{
						"enable-audit": {
							"operation": "update",
							"path": "sys/audit/stdout",
							"data": {
								"type": "file",
								"options": {
									"file_path": "stdout"
								}
							}
						}
					}
				]
			}
		}
	],
	"storage": {"inmem": {}}
}`

const selfInitJSONInitializeLast = `{
	"storage": {"inmem": {}},
	"initialize": [
		{
			"audit": {
				"request": [
					{
						"enable-audit": {
							"operation": "update",
							"path": "sys/audit/stdout",
							"data": {
								"type": "file",
								"options": {
									"file_path": "stdout"
								}
							}
						}
					}
				]
			}
		}
	]
}`

func TestParseConfig_JSONSelfInitNoUnusedFields(t *testing.T) {
	for name, config := range map[string]string{
		"initialize-first-key": selfInitJSONInitializeFirst,
		"initialize-last-key":  selfInitJSONInitializeLast,
	} {
		t.Run(name, func(t *testing.T) {
			conf, err := ParseConfig(config, "")
			if err != nil {
				t.Fatalf("ParseConfig error: %v", err)
			}
			if len(conf.Initialization) != 1 {
				t.Fatalf("expected 1 initialize block, got %d", len(conf.Initialization))
			}
			if conf.Initialization[0].Type != "audit" {
				t.Errorf("expected initialize block type %q, got %q", "audit", conf.Initialization[0].Type)
			}
			if len(conf.Initialization[0].Requests) != 1 {
				t.Fatalf("expected 1 request, got %d", len(conf.Initialization[0].Requests))
			}

			for _, configErr := range conf.Validate("") {
				t.Errorf("unexpected config validation error: %s", configErr.Problem)
			}
		})
	}
}

// A genuinely unknown key inside the initialize stanza must still be
// reported, so consuming block names cannot silently swallow real typos.
func TestParseConfig_JSONSelfInitUnknownFieldStillReported(t *testing.T) {
	config := `{
	"initialize": [
		{
			"audit": {
				"request": [
					{"enable-audit": {"operation": "update", "path": "sys/audit/stdout"}}
				],
				"reqeust_typo": true
			}
		}
	],
	"storage": {"inmem": {}}
}`

	conf, err := ParseConfig(config, "")
	if err != nil {
		t.Fatalf("ParseConfig error: %v", err)
	}

	var found bool
	for _, configErr := range conf.Validate("") {
		if strings.Contains(configErr.Problem, "reqeust_typo") {
			found = true
		}
	}
	if !found {
		t.Fatalf("expected unknown field %q to be reported; got errors: %v", "reqeust_typo", conf.Validate(""))
	}
}
