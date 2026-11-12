package httpadapter_test

import (
	"slices"
	"strings"
	"testing"

	"github.com/code-corhuila/multi-tour-security/internal/core/account"
	"github.com/getkin/kin-openapi/openapi3"
)

// HU-SEC-006, AC8 (RN-SEC-005-02, R4) and the debt of HU-SEC-005 (D-08): what the tested contract must never offer. "Not offered" is
// something that can fail: the rules walk the contract and report every operation or property that breaks them, and a last test shows
// that they do report each operation or property that this test adds to a copy of the contract.

const (
	ruleCreates = "no route creates a permission or a role"
	ruleChanges = "no route changes the role of a user"
)

// the only actions on a user that the contract offers; a new one is a decision, so it has to be added here on purpose
var knownUserActions = []string{"inactivation", "reactivation", "temporary-credential", "permission-grant", "permission-removal"}

func loadContract(t *testing.T) *openapi3.T {
	t.Helper()
	doc, err := openapi3.NewLoader().LoadFromFile("../../../openapi/openapi.yaml")
	if err != nil {
		t.Fatal(err)
	}
	return doc
}

// the roles that exist: the five of a tenant's staff, the customer and the platform
func closedRoles() []string {
	return append(account.InternalRoles(), "FINAL_CUSTOMER", account.RolePlatformAdministrator)
}

// enumOf is the values a schema admits when it names them, also through allOf, oneOf and anyOf; empty when any part admits any value.
func enumOf(ref *openapi3.SchemaRef) []string {
	if ref == nil || ref.Value == nil {
		return nil
	}
	var values []string
	for _, v := range ref.Value.Enum {
		s, _ := v.(string)
		values = append(values, s)
	}
	if len(values) > 0 {
		return values
	}
	for _, group := range [][]*openapi3.SchemaRef{ref.Value.AllOf, ref.Value.OneOf, ref.Value.AnyOf} {
		for _, part := range group {
			inner := enumOf(part)
			if len(inner) == 0 {
				return nil
			}
			values = append(values, inner...)
		}
	}
	return values
}

// roots are every schema the contract declares, in the components and inline in each operation: its parameters, request body and answers.
func roots(doc *openapi3.T) []*openapi3.SchemaRef {
	var out []*openapi3.SchemaRef
	for _, ref := range doc.Components.Schemas {
		out = append(out, ref)
	}
	for _, item := range doc.Paths.Map() {
		for _, op := range item.Operations() {
			out = append(out, bodySchemas(op)...)
			for _, p := range op.Parameters {
				if p.Value != nil && p.Value.Schema != nil {
					out = append(out, p.Value.Schema)
				}
			}
			if op.Responses != nil {
				for _, resp := range op.Responses.Map() {
					if resp.Value != nil {
						for _, media := range resp.Value.Content {
							out = append(out, media.Schema)
						}
					}
				}
			}
		}
	}
	return out
}

func bodySchemas(op *openapi3.Operation) []*openapi3.SchemaRef {
	var out []*openapi3.SchemaRef
	if op.RequestBody != nil && op.RequestBody.Value != nil {
		for _, media := range op.RequestBody.Value.Content {
			out = append(out, media.Schema)
		}
	}
	return out
}

// walk visits every property of every schema reachable from the roots, once per schema, however deep: in objects, arrays, compositions
// and additional properties.
func walk(roots []*openapi3.SchemaRef, visit func(name string, schema *openapi3.SchemaRef)) {
	seen := map[*openapi3.Schema]bool{}
	var in func(ref *openapi3.SchemaRef)
	in = func(ref *openapi3.SchemaRef) {
		if ref == nil || ref.Value == nil || seen[ref.Value] {
			return
		}
		seen[ref.Value] = true
		for name, prop := range ref.Value.Properties {
			visit(name, prop)
			in(prop)
		}
		in(ref.Value.Items)
		if ref.Value.AdditionalProperties.Schema != nil {
			in(ref.Value.AdditionalProperties.Schema)
		}
		for _, group := range [][]*openapi3.SchemaRef{ref.Value.AllOf, ref.Value.OneOf, ref.Value.AnyOf} {
			for _, part := range group {
				in(part)
			}
		}
	}
	for _, ref := range roots {
		in(ref)
	}
}

// requestNames are the names of every property of the request body of an operation, however deep, and of its query, header and cookie
// parameters: a role or a permission can travel in any of them.
func requestNames(op *openapi3.Operation) []string {
	var names []string
	walk(bodySchemas(op), func(name string, _ *openapi3.SchemaRef) { names = append(names, name) })
	for _, p := range op.Parameters {
		if p.Value != nil && p.Value.In != "path" {
			names = append(names, p.Value.Name)
		}
	}
	return names
}

// lastSegment is the last part of the path that is not a parameter.
func lastSegment(path string) string {
	parts := strings.Split(strings.Trim(path, "/"), "/")
	for i := len(parts) - 1; i >= 0; i-- {
		if !strings.HasPrefix(parts[i], "{") {
			return parts[i]
		}
	}
	return ""
}

// aboutRoles tells a segment that names a role or a permission, in the singular or the plural and inside a longer name.
func aboutRoles(segment string) bool {
	segment = strings.ToLower(segment)
	return strings.Contains(segment, "role") || strings.Contains(segment, "permission")
}

// broken lists what the contract offers that it must not: each line begins with the rule it breaks.
func broken(doc *openapi3.T) []string {
	var out []string
	roles, permissions := closedRoles(), account.SpecialPermissions()
	for path, item := range doc.Paths.Map() {
		for method, op := range item.Operations() {
			writes := method == "POST" || method == "PUT" || method == "PATCH"
			// a route that makes a permission or a role: a write on a collection of them
			switch lastSegment(path) {
			case "permissions", "permission", "roles", "role", "optional-roles":
				if writes {
					out = append(out, ruleCreates+": "+method+" "+path)
				}
			}
			// a route that changes the user: anything under a user that is not one of the known actions, or that carries a role
			if strings.Contains(path, "/users/{") && (writes || method == "DELETE") {
				if !slices.Contains(knownUserActions, lastSegment(path)) || (method != "POST") || strings.HasSuffix(path, "}") {
					out = append(out, ruleChanges+": "+method+" "+path+" is not one of the known actions on a user")
				}
				for _, name := range requestNames(op) {
					if name == "role" || name == "roles" {
						out = append(out, ruleChanges+": "+method+" "+path+" takes "+name)
					}
				}
			}
			// a role or a permission that travels in a query, a header or a cookie, on any route
			for _, p := range op.Parameters {
				if p.Value != nil && p.Value.In != "path" && aboutRoles(p.Value.Name) && !(method == "GET" && p.Value.In == "query" && p.Value.Name == "role" && path == "/api/v1/security/users") {
					out = append(out, ruleChanges+": "+method+" "+path+" takes "+p.Value.Name+" in the "+p.Value.In)
				}
			}
		}
	}
	walk(roots(doc), func(name string, prop *openapi3.SchemaRef) {
		switch name {
		case "permission":
			if values := enumOf(prop); len(values) == 0 || slices.ContainsFunc(values, func(v string) bool { return !slices.Contains(permissions, v) }) {
				out = append(out, ruleCreates+": a property permission admits "+strings.Join(values, ",")+" or any value")
			}
		case "role":
			if values := enumOf(prop); len(values) == 0 || slices.ContainsFunc(values, func(v string) bool { return !slices.Contains(roles, v) }) {
				out = append(out, ruleCreates+": a property role admits "+strings.Join(values, ",")+" or any value")
			}
		case "permissions":
			if prop.Value != nil && prop.Value.Items != nil {
				if values := enumOf(prop.Value.Items); len(values) == 0 || slices.ContainsFunc(values, func(v string) bool { return !slices.Contains(permissions, v) }) {
					out = append(out, ruleCreates+": the permissions of a property admit "+strings.Join(values, ",")+" or any value")
				}
			}
		}
	})
	slices.Sort(out)
	return slices.Compact(out)
}

func violations(t *testing.T, rule string) []string {
	t.Helper()
	var got []string
	for _, line := range broken(loadContract(t)) {
		if strings.HasPrefix(line, rule) {
			got = append(got, line)
		}
	}
	return got
}

func TestC_NoRouteCreatesAPermissionOrARole(t *testing.T) {
	if got := violations(t, ruleCreates); len(got) != 0 {
		t.Fatalf("the contract offers what it must not:\n%s", strings.Join(got, "\n"))
	}
}

func TestC_NoRouteChangesTheRoleOfAUser(t *testing.T) {
	if got := violations(t, ruleChanges); len(got) != 0 {
		t.Fatalf("the contract offers what it must not:\n%s", strings.Join(got, "\n"))
	}
}

// the rules must be able to fail: each copy of the contract has one operation or property added by this test, and the rules name it
func TestC_TheRulesReportEachOperationOrPropertyThatBreaksThemAndNothingThatDoesNot(t *testing.T) {
	object := func(props map[string]*openapi3.Schema) *openapi3.Schema {
		body := openapi3.NewObjectSchema()
		for name, s := range props {
			body = body.WithProperty(name, s)
		}
		return body
	}
	post := func(id string, props map[string]*openapi3.Schema) *openapi3.PathItem {
		op := &openapi3.Operation{OperationID: id, Responses: openapi3.NewResponses()}
		if props != nil {
			op.RequestBody = &openapi3.RequestBodyRef{Value: openapi3.NewRequestBody().WithJSONSchema(object(props))}
		}
		return &openapi3.PathItem{Post: op}
	}
	closed := openapi3.NewStringSchema().WithEnum("MANAGER")
	cases := []struct {
		name     string
		rule     string
		mutate   func(*openapi3.T)
		reported bool
	}{
		{"a route that creates permissions", ruleCreates, func(d *openapi3.T) { d.Paths.Set("/api/v1/security/permissions", post("createPermission", nil)) }, true},
		{"a route that creates roles", ruleCreates, func(d *openapi3.T) { d.Paths.Set("/api/v1/security/roles", post("createRole", nil)) }, true},
		{"a route that creates optional roles", ruleCreates, func(d *openapi3.T) { d.Paths.Set("/api/v1/security/optional-roles", post("createOptionalRole", nil)) }, true},
		{"a permission that admits any value", ruleCreates, func(d *openapi3.T) {
			d.Components.Schemas["FreePermission"] = openapi3.NewSchemaRef("", object(map[string]*openapi3.Schema{"permission": openapi3.NewStringSchema()}))
		}, true},
		{"a permission outside the four", ruleCreates, func(d *openapi3.T) {
			d.Components.Schemas["PermissionChangeRequest"].Value.Properties["permission"] = openapi3.NewSchemaRef("", openapi3.NewStringSchema().WithEnum("MANAGE_CASH", "CUSTOM_PERMISSION"))
		}, true},
		{"a role outside the closed set", ruleCreates, func(d *openapi3.T) {
			d.Components.Schemas["CreateInternalUserRequest"].Value.Properties["role"] = openapi3.NewSchemaRef("", openapi3.NewStringSchema().WithEnum("MANAGER", "SUPERUSER"))
		}, true},
		{"a free role in an answer", ruleCreates, func(d *openapi3.T) {
			d.Components.Schemas["OptionalRoleState"].Value.Properties["role"] = openapi3.NewSchemaRef("", openapi3.NewStringSchema())
		}, true},
		{"a free list of permissions", ruleCreates, func(d *openapi3.T) {
			d.Components.Schemas["FreePermissions"] = openapi3.NewSchemaRef("", object(map[string]*openapi3.Schema{"permissions": openapi3.NewArraySchema().WithItems(openapi3.NewStringSchema())}))
		}, true},
		{"a role declared inline in an operation and free", ruleCreates, func(d *openapi3.T) {
			d.Paths.Set("/api/v1/security/users/{accountId}/inactivation", &openapi3.PathItem{Post: &openapi3.Operation{OperationID: "inactivateInternalUser",
				RequestBody: &openapi3.RequestBodyRef{Value: openapi3.NewRequestBody().WithJSONSchema(object(map[string]*openapi3.Schema{"role": openapi3.NewStringSchema()}))},
				Responses:   openapi3.NewResponses()}})
		}, true},
		{"a route named after a role with no body", ruleChanges, func(d *openapi3.T) { d.Paths.Set("/api/v1/security/users/{accountId}/role", post("changeRole", nil)) }, true},
		{"a route that gives a user other roles", ruleChanges, func(d *openapi3.T) {
			d.Paths.Set("/api/v1/security/users/{accountId}/promotion", post("promote", map[string]*openapi3.Schema{"roles": openapi3.NewArraySchema()}))
		}, true},
		{"an unknown action on a user with no body and a new name", ruleChanges, func(d *openapi3.T) {
			d.Paths.Set("/api/v1/security/users/{accountId}/roles-change", post("changeRoles", nil))
		}, true},
		{"a route that replaces a user as a whole", ruleChanges, func(d *openapi3.T) {
			d.Paths.Set("/api/v1/security/users/{accountId}", &openapi3.PathItem{Put: &openapi3.Operation{OperationID: "replaceUser", Responses: openapi3.NewResponses()}})
		}, true},
		{"a patch on a user", ruleChanges, func(d *openapi3.T) {
			d.Paths.Set("/api/v1/security/users/{accountId}", &openapi3.PathItem{Patch: &openapi3.Operation{OperationID: "patchUser", Responses: openapi3.NewResponses()}})
		}, true},
		{"a delete of a user", ruleChanges, func(d *openapi3.T) {
			d.Paths.Set("/api/v1/security/users/{accountId}", &openapi3.PathItem{Delete: &openapi3.Operation{OperationID: "deleteUser", Responses: openapi3.NewResponses()}})
		}, true},
		{"a role in the query of an action on a user", ruleChanges, func(d *openapi3.T) {
			item := d.Paths.Find("/api/v1/security/users/{accountId}/reactivation")
			item.Post.Parameters = append(item.Post.Parameters, &openapi3.ParameterRef{Value: openapi3.NewQueryParameter("newRole").WithSchema(openapi3.NewStringSchema())})
		}, true},
		// what is allowed must not be reported: a role that is a composition of the closed set, and the role of the creation of a user
		{"a role composed of the closed enum", ruleCreates, func(d *openapi3.T) {
			wrapper := openapi3.NewSchema()
			wrapper.AllOf = openapi3.SchemaRefs{openapi3.NewSchemaRef("", closed)}
			d.Components.Schemas["OptionalRoleState"].Value.Properties["role"] = openapi3.NewSchemaRef("", wrapper)
		}, false},
	}
	for _, c := range cases {
		doc := loadContract(t)
		c.mutate(doc)
		found := false
		for _, line := range broken(doc) {
			found = found || strings.HasPrefix(line, c.rule)
		}
		if found != c.reported {
			t.Errorf("%s: the rule %q reported it = %v, want %v: %v", c.name, c.rule, found, c.reported, broken(doc))
		}
	}
	if clean := broken(loadContract(t)); len(clean) != 0 {
		t.Fatalf("the contract as it is must break nothing: %v", clean)
	}
}
