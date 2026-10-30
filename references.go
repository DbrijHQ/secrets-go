package dbrijsecrets

// Dbrij Secrets references (B5): a value saved as a template, filled in where it is read.
// The same rules as packages/shared/src/secret-references.ts and the Node and Python SDKs:
//
//	${KEY}                    KEY in the same folder
//	${/api.KEY}               KEY in the folder /api of the same environment (${/.KEY}: the top)
//	${production.KEY}         KEY at the top of the environment called production
//	${production./api.KEY}    KEY in /api of production
//
// Only a value saved as a template (it carries its references) is filled in. A reference
// that cannot be filled leaves its secret out, with a problem naming it: never empty.

import (
	"regexp"
	"strings"
)

const maxRefDepth = 5

var refToken = regexp.MustCompile(`\$\{(?:([a-z0-9][a-z0-9_]{0,39})\.)?(?:(/(?:[a-z0-9_]{1,40}(?:/[a-z0-9_]{1,40})*)?)\.)?([A-Za-z_][A-Za-z0-9_]*)\}`)

// SecretsRef is where a reference points. Environment empty: the template's own environment.
type SecretsRef struct {
	Environment *string `json:"environment"`
	Path        string  `json:"path"`
	Key         string  `json:"key"`
}

func refID(environment, path, key string) string { return environment + "|" + path + "|" + key }

func refLabel(environment, path, key string) string {
	out := ""
	if environment != "" {
		out = environment + " "
	}
	if path != "/" {
		out += path + "."
	}
	return out + key
}

// fillTemplate fills each reference through lookup, or stops at the first one it cannot fill.
func fillTemplate(template, ownPath string, lookup func(environment, path, key string) (string, string)) (string, string) {
	problem := ""
	var out strings.Builder
	last := 0
	for _, m := range refToken.FindAllStringSubmatchIndex(template, -1) {
		out.WriteString(template[last:m[0]])
		last = m[1]
		if problem != "" {
			continue
		}
		group := func(i int) (string, bool) {
			if m[2*i] < 0 {
				return "", false
			}
			return template[m[2*i]:m[2*i+1]], true
		}
		env, hasEnv := group(1)
		path, hasPath := group(2)
		key, _ := group(3)
		if !hasPath {
			path = ownPath
			if hasEnv {
				path = "/"
			}
		}
		value, issue := lookup(env, path, key)
		if issue != "" {
			problem = issue
			continue
		}
		// Written as it is: a value's own $ signs mean nothing here.
		out.WriteString(value)
	}
	out.WriteString(template[last:])
	if problem != "" {
		return "", problem
	}
	return out.String(), ""
}
