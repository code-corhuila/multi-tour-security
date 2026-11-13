package main

import (
	"os"
	"strings"
	"testing"
)

// The key of the HMAC of the recovery codes (spec 006-hu-sec-004, plan D-02, task REC-07).

func TestC_StartupFailsWithoutTheRecoveryCodeKeyAndSaysWhich(t *testing.T) {
	_, err := loadConfig(environment(writeKeys(t, 2048), map[string]string{"RECOVERY_CODE_KEY": ""}), os.ReadFile)
	if err == nil || !strings.Contains(err.Error(), "RECOVERY_CODE_KEY") {
		t.Fatalf("err = %v, want it to name RECOVERY_CODE_KEY", err)
	}
}

func TestC_AShortRecoveryCodeKeyStopsTheStartAndIsNeverEchoed(t *testing.T) {
	short := "not-enough-bytes-for-a-key"
	_, err := loadConfig(environment(writeKeys(t, 2048), map[string]string{"RECOVERY_CODE_KEY": short}), os.ReadFile)
	if err == nil || !strings.Contains(err.Error(), "RECOVERY_CODE_KEY") || !strings.Contains(err.Error(), "32") {
		t.Fatalf("err = %v, want it to name the variable and the minimum", err)
	}
	if strings.Contains(err.Error(), short) {
		t.Fatalf("the error quotes the secret: %v", err)
	}
}

func TestC_AValidRecoveryCodeKeyIsKeptAndNeverPrinted(t *testing.T) {
	key := strings.Repeat("k", 32) + "-not-for-the-log"
	cfg, err := loadConfig(environment(writeKeys(t, 2048), map[string]string{"RECOVERY_CODE_KEY": key}), os.ReadFile)
	if err != nil {
		t.Fatal(err)
	}
	if string(cfg.recoveryKey) != key {
		t.Fatal("the key was not kept as it was given")
	}
	for _, printed := range []string{cfg.String(), cfg.GoString()} {
		if strings.Contains(printed, key) {
			t.Fatalf("the key is in a printed value: %s", printed)
		}
	}
}

func TestC_TheRecoveryCodeKeyIsDocumentedWhereItIsSet(t *testing.T) {
	for _, file := range []string{"../../.env.example", "../../deploy/compose.yml", "../../README.md"} {
		raw, err := os.ReadFile(file)
		if err != nil {
			t.Fatal(err)
		}
		if !strings.Contains(string(raw), "RECOVERY_CODE_KEY") {
			t.Errorf("%s does not mention RECOVERY_CODE_KEY", file)
		}
	}
	example, _ := os.ReadFile("../../.env.example")
	for _, line := range strings.Split(string(example), "\n") {
		if strings.HasPrefix(line, "RECOVERY_CODE_KEY=") && strings.TrimPrefix(line, "RECOVERY_CODE_KEY=") != "" {
			t.Errorf(".env.example carries a value for the key: %s", line)
		}
	}
}
