package main

import (
	"os"
	"strings"
	"testing"
)

// What an operator reads must be what the commands read: a variable the example misnames is a command that fails in
// the first deployment, and a command the README does not mention is one nobody runs.

func fileOf(t *testing.T, path string) string {
	t.Helper()
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return string(raw)
}

func TestC_TheEnvironmentExampleNamesTheVariablesTheCommandsRead(t *testing.T) {
	example := fileOf(t, "../../.env.example")
	for _, name := range []string{"PLATFORM_ADMIN_EMAIL=", "JWT_PRIVATE_KEY_FILE=", "JWT_PUBLIC_KEY_FILE=", "DATABASE_URL=", "HTTP_PORT="} {
		if !strings.Contains("\n"+example, "\n"+name) {
			t.Errorf("the example does not name %s", name)
		}
	}
	if strings.Contains(example, "BOOTSTRAP_ADMIN_EMAIL") {
		t.Error("the example names a variable that no command reads")
	}
}

func TestC_TheReadmeExplainsBothCommandsAndNoLongerCallsThemMissing(t *testing.T) {
	readme := fileOf(t, "../../README.md")
	for _, want := range []string{"bootstrap-platform-admin", "issue-service-token", "PLATFORM_ADMIN_EMAIL"} {
		if !strings.Contains(readme, want) {
			t.Errorf("the README does not mention %s", want)
		}
	}
	if strings.Contains(readme, "For now the schema holds") || strings.Contains(readme, "## What is missing") {
		t.Error("the README still says that what exists is missing")
	}
}
