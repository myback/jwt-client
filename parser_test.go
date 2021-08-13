package jwt

import (
	"reflect"
	"testing"
)

func TestAccessEntry_ToString(t *testing.T) {
	type fields struct {
		actions   actions
		namespace string
		_type     string
	}
	tests := []struct {
		name  string
		token string
		want  string
	}{
		{"ScopeToStringPull", "scope=\"repository:test/example:pull\"", "repository:test/example:pull"},
		{"ScopeToStringPush", "scope=\"repository:test/example:push\"", "repository:test/example:push"},
		{"ScopeToStringPullPush", "scope=\"repository:test/example:push,pull\"", "repository:test/example:pull,push"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			a := WWWAuthHeaderParse(tt.token)
			if got := a.Scope.ToString(); got != tt.want {
				t.Errorf("ToString() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestWWWAuthHeaderParse(t *testing.T) {
	type args struct {
		s string
	}
	tests := []struct {
		name string
		args args
		want *WWWAuthenticate
	}{
		{"WWWAuthenticateNone", args{"Bearer realm=\"https://registry.example.com/jwt/auth\",service=\"container_registry\",scope=\"repository:test/example:\""}, &WWWAuthenticate{
			Scope:   &Scope{ActionsNone, "test/example", "repository"},
			Service: "container_registry",
			Realm:   "https://registry.example.com/jwt/auth",
		}},
		{"WWWAuthenticatePull", args{"Bearer realm=\"https://registry.example.com/jwt/auth\",service=\"container_registry\",scope=\"repository:test/example:pull\""}, &WWWAuthenticate{
			Scope:   &Scope{ActionsPull, "test/example", "repository"},
			Service: "container_registry",
			Realm:   "https://registry.example.com/jwt/auth",
		}},
		{"WWWAuthenticatePush", args{"Bearer realm=\"https://registry.example.com/jwt/auth\",service=\"container_registry\",scope=\"repository:test/example:push\""}, &WWWAuthenticate{
			Scope:   &Scope{ActionsPush, "test/example", "repository"},
			Service: "container_registry",
			Realm:   "https://registry.example.com/jwt/auth",
		}},
		{"WWWAuthenticatePullPush", args{"Bearer realm=\"https://registry.example.com/jwt/auth\",service=\"container_registry\",scope=\"repository:test/example:pull,push\""}, &WWWAuthenticate{
			Scope:   &Scope{ActionsAll, "test/example", "repository"},
			Service: "container_registry",
			Realm:   "https://registry.example.com/jwt/auth",
		}},
		{"WWWAuthenticateInvalidScope", args{"Bearer realm=\"https://registry.example.com/jwt/auth\",service=\"container_registry\",scope=\"repository:test/example\""}, nil},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := WWWAuthHeaderParse(tt.args.s); !reflect.DeepEqual(got, tt.want) {
				t.Errorf("WWWAuthHeaderParse() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestWWWAuthenticate_SetActions(t *testing.T) {
	type args struct {
		act actions
	}
	tests := []struct {
		name  string
		token string
		args  args
		want  *Scope
	}{
		{"WWWAuthenticateSetActionsPull", "scope=\"repository:test/example:\"", args{ActionsPull}, &Scope{ActionsPull, "test/example", "repository"}},
		{"WWWAuthenticateSetActionsPush", "scope=\"repository:test/example:pull\"", args{ActionsPush}, &Scope{ActionsPush, "test/example", "repository"}},
		{"WWWAuthenticateSetActionsAll", "scope=\"repository:test/example:pull\"", args{ActionsAll}, &Scope{ActionsAll, "test/example", "repository"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			wa := WWWAuthHeaderParse(tt.token)
			got := wa.SetActions(tt.args.act)

			if reflect.DeepEqual(wa.Scope, tt.want) {
				t.Errorf("%v and %v was be different", wa.Scope, tt.want)
			}
			if !reflect.DeepEqual(got.Scope, tt.want) {
				t.Errorf("SetActions() = %v, want %v", got.Scope, tt.want)
			}
		})
	}
}

func TestWWWAuthenticate_Url(t *testing.T) {
	tests := []struct {
		name    string
		token   string
		want    string
		wantErr bool
	}{
		{"WWWAuthenticateUrlPull", "Bearer realm=\"https://registry.example.com/jwt/auth\",service=\"container_registry\",scope=\"repository:test/example:pull\"", "https://registry.example.com/jwt/auth?scope=repository%3Atest%2Fexample%3Apull&service=container_registry", false},
		{"WWWAuthenticateUrlPush", "Bearer realm=\"https://registry.example.com/jwt/auth\",service=\"container_registry\",scope=\"repository:test/example:push\"", "https://registry.example.com/jwt/auth?scope=repository%3Atest%2Fexample%3Apush&service=container_registry", false},
		{"WWWAuthenticateUrlAll", "Bearer realm=\"https://registry.example.com/jwt/auth\",service=\"container_registry\",scope=\"repository:test/example:pull,push\"", "https://registry.example.com/jwt/auth?scope=repository%3Atest%2Fexample%3Apull%2Cpush&service=container_registry", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			wa := WWWAuthHeaderParse(tt.token)
			got, err := wa.Url()
			if (err != nil) != tt.wantErr {
				t.Errorf("Url() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if got != tt.want {
				t.Errorf("Url() got = %v, want %v", got, tt.want)
			}
		})
	}
}
