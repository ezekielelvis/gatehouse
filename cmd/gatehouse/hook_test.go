package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestWriteHookBacksUpForeignHook(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "pre-commit")
	if err := os.WriteFile(path, []byte("#!/bin/sh\necho mine\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := writeHook(path, preCommitHook); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(path + ".pre-gatehouse"); err != nil {
		t.Fatal("foreign hook should have been backed up")
	}
	got, _ := os.ReadFile(path)
	if !strings.Contains(string(got), hookMarker) {
		t.Fatal("gatehouse hook not written")
	}
}

func TestWriteHookNoBackupForOwnHook(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "pre-push")
	// First install writes our hook; second must not create a backup.
	if err := writeHook(path, prePushHook); err != nil {
		t.Fatal(err)
	}
	if err := writeHook(path, prePushHook); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(path + ".pre-gatehouse"); err == nil {
		t.Fatal("re-installing our own hook must not create a backup")
	}
}

func TestDetectHookManager(t *testing.T) {
	dir := t.TempDir()
	if detectHookManager(dir) != "" {
		t.Fatal("empty repo should have no manager")
	}
	if err := os.WriteFile(filepath.Join(dir, "lefthook.yml"), []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	if got := detectHookManager(dir); got != "Lefthook" {
		t.Fatalf("want Lefthook, got %q", got)
	}
}
