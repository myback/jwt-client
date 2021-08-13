package jwt

import (
	"fmt"
	"net/url"
	"reflect"
	"strings"
	"unicode"
)

type actions string

const (
	ActionsNone actions = ""
	ActionsPull actions = "pull"
	ActionsPush actions = "push"
	ActionsAll  actions = "pull,push"
)

type Scope struct {
	actions   actions
	namespace string
	_type     string
}

func (a *Scope) ToString() string {
	return fmt.Sprintf("%s:%s:%s", a._type, a.namespace, a.actions)
}

type WWWAuthenticate struct {
	Scope   *Scope
	Service string
	Realm   string
}

func parseActions(s string) actions {
	switch s {
	case "pull":
		return ActionsPull
	case "push":
		return ActionsPush
	case "":
		return ActionsNone
	default:
		return ActionsAll
	}
}

func trim(s string) string {
	return strings.Trim(s, ",\" ")
}

func WWWAuthHeaderParse(s string) *WWWAuthenticate {
	header := strings.TrimPrefix(s, "Bearer ")

	lastQuote := rune(0)
	f := func(c rune) bool {
		switch {
		case c == lastQuote:
			lastQuote = rune(0)
			return false
		case lastQuote != rune(0):
			return false
		case unicode.In(c, unicode.Quotation_Mark):
			lastQuote = c
			return false
		default:
			return string(c) == ","

		}
	}

	out := &WWWAuthenticate{}
	elem := reflect.ValueOf(out).Elem()
	for _, item := range strings.FieldsFunc(header, f) {
		kv := strings.SplitN(item, "=", 2)
		key := trim(kv[0])
		val := trim(kv[1])

		field := elem.FieldByName(strings.Title(key))

		if strings.ToLower(key) != "scope" {
			field.SetString(val)
			continue
		}

		parts := strings.Split(val, ":")
		if len(parts) != 3 {
			return nil
		}

		entry := &Scope{
			actions:   parseActions(parts[2]),
			namespace: parts[1],
			_type:     parts[0],
		}

		field.Set(reflect.ValueOf(entry))
	}

	return out
}

func (wa *WWWAuthenticate) SetActions(act actions) *WWWAuthenticate {
	newAuth := &WWWAuthenticate{}
	*newAuth = *wa
	newAuth.Scope = &Scope{}
	*newAuth.Scope = *wa.Scope

	newAuth.Scope.actions = act

	return newAuth
}

func (wa *WWWAuthenticate) Url() (string, error) {
	u, err := url.Parse(wa.Realm)
	if err != nil {
		return "", nil
	}
	q, err := url.ParseQuery(u.RawQuery)
	if err != nil {
		return "", nil
	}

	q.Set("service", wa.Service)
	q.Set("scope", wa.Scope.ToString())

	u.RawQuery = q.Encode()

	return u.String(), nil
}
