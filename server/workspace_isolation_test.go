package server

import (
	"bytes"
	"encoding/json"
	"io"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// The worker may replace or rename any directory it owns. Operations must
// remain bound to an already-open directory handle rather than its old name.
func TestWorkspaceAtomicWriteKeepsPinnedParentAfterSwap(t *testing.T) {
	data := t.TempDir()
	outside := t.TempDir()
	if err := os.Mkdir(filepath.Join(data, "uploads"), 0o755); err != nil {
		t.Fatal(err)
	}
	secret := filepath.Join(outside, "secret.txt")
	if err := os.WriteFile(secret, []byte("keep"), 0o600); err != nil {
		t.Fatal(err)
	}
	root, err := os.OpenRoot(data)
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close()
	parent, err := root.OpenRoot("uploads")
	if err != nil {
		t.Fatal(err)
	}
	defer parent.Close()

	if err := os.Rename(filepath.Join(data, "uploads"), filepath.Join(data, "moved")); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, filepath.Join(data, "uploads")); err != nil {
		t.Skipf("symlink unsupported: %v", err)
	}
	if err := workspaceAtomicWrite(parent, "report.txt", strings.NewReader("inside")); err != nil {
		t.Fatal(err)
	}
	b, err := os.ReadFile(filepath.Join(data, "moved", "report.txt"))
	if err != nil || string(b) != "inside" {
		t.Fatalf("write missed pinned parent: data=%q error=%v", b, err)
	}
	if _, err := os.Stat(filepath.Join(outside, "report.txt")); !os.IsNotExist(err) {
		t.Fatalf("write escaped via swapped parent: %v", err)
	}
	if b, _ := os.ReadFile(secret); string(b) != "keep" {
		t.Fatal("outside secret modified")
	}
	if badRoot, err := root.OpenRoot("uploads"); err == nil {
		badRoot.Close()
		t.Fatal("confined root followed outside-directory symlink")
	}
}

func TestWorkspaceAtomicWriteRejectsFinalSymlinkAndDirectory(t *testing.T) {
	data := t.TempDir()
	outside := t.TempDir()
	target := filepath.Join(outside, "target")
	if err := os.WriteFile(target, []byte("secret"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(target, filepath.Join(data, "link")); err != nil {
		t.Skipf("symlink unsupported: %v", err)
	}
	if err := os.Mkdir(filepath.Join(data, "directory"), 0o755); err != nil {
		t.Fatal(err)
	}
	root, err := os.OpenRoot(data)
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close()
	for _, path := range []string{"link", "directory", "../escape", "/outside"} {
		if err := workspaceAtomicWrite(root, path, strings.NewReader("overwritten")); err == nil {
			t.Errorf("accepted untrusted destination %q", path)
		}
	}
	if b, _ := os.ReadFile(target); string(b) != "secret" {
		t.Fatalf("symlink target was overwritten: %q", b)
	}
}

func TestWorkspaceAtomicWriteKeepsExistingPermissions(t *testing.T) {
	data := t.TempDir()
	file := filepath.Join(data, "private.txt")
	if err := os.WriteFile(file, []byte("original"), 0o600); err != nil {
		t.Fatal(err)
	}
	root, err := os.OpenRoot(data)
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close()
	if err := workspaceAtomicWrite(root, "private.txt", strings.NewReader("updated")); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(file)
	if err != nil {
		t.Fatal(err)
	}
	if got := info.Mode().Perm(); got != 0o600 {
		t.Errorf("atomic replacement changed original permissions to %04o", got)
	}
}

func TestWorkspaceRootedDeleteKeepsPinnedParent(t *testing.T) {
	data := t.TempDir()
	outside := t.TempDir()
	if err := os.MkdirAll(filepath.Join(data, "area", "nested"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(data, "area", "nested", "file"), []byte("yes"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(outside, "keep"), []byte("outside"), 0o644); err != nil {
		t.Fatal(err)
	}
	root, err := os.OpenRoot(data)
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close()
	parent, err := root.OpenRoot("area")
	if err != nil {
		t.Fatal(err)
	}
	defer parent.Close()
	if err := os.Rename(filepath.Join(data, "area"), filepath.Join(data, "moved")); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, filepath.Join(data, "area")); err != nil {
		t.Skipf("symlink unsupported: %v", err)
	}
	if err := parent.RemoveAll("nested"); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(data, "moved", "nested")); !os.IsNotExist(err) {
		t.Fatalf("rooted delete did not remove expected subtree: %v", err)
	}
	if b, _ := os.ReadFile(filepath.Join(outside, "keep")); string(b) != "outside" {
		t.Fatal("rooted delete affected outside directory")
	}
}

func TestWorkspaceHandlersRootedFileLifecycle(t *testing.T) {
	data := t.TempDir()
	s := &Server{m: &Manager{dir: data}}
	call := func(h http.HandlerFunc, method, url string, body io.Reader) *httptest.ResponseRecorder {
		rec := httptest.NewRecorder()
		h(rec, httptest.NewRequest(method, url, body))
		return rec
	}

	// mkdir and write never open absolute paths beyond the workspace root.
	if rec := call(s.wsMkdir, "POST", "/api/workspace/mkdir", strings.NewReader(`{"path":"notes"}`)); rec.Code != 200 {
		t.Fatalf("mkdir=%d: %s", rec.Code, rec.Body.String())
	}
	if rec := call(s.wsWrite, "POST", "/api/workspace/write", strings.NewReader(`{"path":"notes/hello.txt","content":"hello"}`)); rec.Code != 200 {
		t.Fatalf("write=%d: %s", rec.Code, rec.Body.String())
	}
	rec := call(s.wsRead, "GET", "/api/workspace/read?path=notes/hello.txt", nil)
	var read struct {
		Content string `json:"content"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &read); err != nil || read.Content != "hello" {
		t.Fatalf("read=%d: %s (%v)", rec.Code, rec.Body.String(), err)
	}
	if rec := call(s.wsList, "GET", "/api/workspace/list?path=notes", nil); rec.Code != 200 {
		t.Fatalf("list=%d: %s", rec.Code, rec.Body.String())
	}
	if rec := call(s.wsDownload, "GET", "/api/workspace/download?path=notes/hello.txt", nil); rec.Code != 200 || rec.Body.String() != "hello" {
		t.Fatalf("download=%d: %s", rec.Code, rec.Body.String())
	}

	// Existing regular destinations can still be overwritten by an upload, but
	// the replacement uses a pinned parent and atomic rename.
	var body bytes.Buffer
	form := multipart.NewWriter(&body)
	part, err := form.CreateFormFile("file", "hello.txt")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := part.Write([]byte("uploaded")); err != nil {
		t.Fatal(err)
	}
	if err := form.Close(); err != nil {
		t.Fatal(err)
	}
	req := httptest.NewRequest("POST", "/api/workspace/upload?path=notes", &body)
	req.Header.Set("Content-Type", form.FormDataContentType())
	uploadRec := httptest.NewRecorder()
	s.wsUpload(uploadRec, req)
	if uploadRec.Code != 200 {
		t.Fatalf("upload=%d: %s", uploadRec.Code, uploadRec.Body.String())
	}
	b, err := os.ReadFile(filepath.Join(data, "notes", "hello.txt"))
	if err != nil || string(b) != "uploaded" {
		t.Fatalf("upload content=%q err=%v", b, err)
	}
	if rec := call(s.wsDelete, "DELETE", "/api/workspace/delete?path=notes", nil); rec.Code != 200 {
		t.Fatalf("delete=%d: %s", rec.Code, rec.Body.String())
	}
	if _, err := os.Stat(filepath.Join(data, "notes")); !os.IsNotExist(err) {
		t.Fatalf("deleted directory still exists: %v", err)
	}
}
