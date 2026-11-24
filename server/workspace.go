package server

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"mime/multipart"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"unicode/utf8"
)

// Workspace file manager — browse / view / edit / download / upload / delete the
// shared work dir (s.m.dir), where all agents write their artifacts. Every path is
// confined to the work dir root (traversal via ".." is neutralised). All routes sit
// behind requireAuth (see Handler()).

const (
	maxWorkspaceRead   = 2 << 20   // 2 MiB: files bigger than this aren't inlined for view/edit (download instead)
	maxWorkspaceUpload = 512 << 20 // 512 MiB per upload request
)

// wsResolveConfined maps a user-supplied relative path to a canonicalized path
// inside the work dir, resolving symlinks in every component and rejecting any
// traversal, broken symlink, symlink loop, or target that escapes s.m.dir.
func (s *Server) wsResolveConfined(rel string) (confinedPath, bool) {
	cp, err := resolveWithinRoot(s.m.dir, rel, true)
	if err != nil {
		return confinedPath{}, false
	}
	if workspacePathDenied(cp.realRoot, cp.realPath) {
		return confinedPath{}, false
	}
	return cp, true
}

// workspaceDeniedPrefixes are platform-internal subtrees under the data dir
// that the workspace file manager must not expose. traffic/_ca holds the
// capture proxy CA private key; traffic/_index holds the SQLite exchange index;
// traffic/_blobs holds the captured bodies the index refers to by hash.
var workspaceDeniedPrefixes = []string{"traffic/_ca", "traffic/_index", "traffic/_blobs"}

// workspacePathDenied reports whether realPath lands in a platform-internal
// subtree. It compares the canonicalized path relative to the real root, so a
// symlink alias cannot reach a denied directory. Segments are lower-cased and
// trailing dots/spaces are trimmed because Windows resolves those spellings to
// the same directory.
func workspacePathDenied(realRoot, realPath string) bool {
	rel, err := filepath.Rel(realRoot, realPath)
	if err != nil {
		return true // fail closed
	}
	rel = filepath.ToSlash(rel)
	if rel == ".." || strings.HasPrefix(rel, "../") || strings.HasPrefix(rel, "/") {
		return true // outside the root: fail closed
	}
	segs := strings.Split(rel, "/")
	for i, seg := range segs {
		segs[i] = strings.ToLower(strings.TrimRight(seg, ". "))
	}
	rel = strings.Join(segs, "/")
	for _, prefix := range workspaceDeniedPrefixes {
		if rel == prefix || strings.HasPrefix(rel, prefix+"/") {
			return true
		}
	}
	return false
}

// workspaceHoldsDenied reports whether a platform-internal subtree lies beneath
// path, so that removing path would remove it too. Segments are normalised as
// in workspacePathDenied.
func workspaceHoldsDenied(realRoot, path string) bool {
	rel, err := filepath.Rel(realRoot, path)
	if err != nil {
		return true // fail closed
	}
	segs := strings.Split(filepath.ToSlash(rel), "/")
	for i, seg := range segs {
		segs[i] = strings.ToLower(strings.TrimRight(seg, ". "))
	}
	rel = strings.Join(segs, "/")
	for _, prefix := range workspaceDeniedPrefixes {
		if strings.HasPrefix(prefix, rel+"/") {
			return true
		}
	}
	return false
}

// wsRel renders an absolute path back as a workspace-relative path (forward slashes).
func (s *Server) wsRel(abs string) string {
	base, err := resolveRealRoot(s.m.dir)
	if err != nil {
		base = filepath.Clean(s.m.dir)
	}
	rel, err := filepath.Rel(base, abs)
	if err != nil || rel == "." {
		return ""
	}
	return filepath.ToSlash(rel)
}

// workspaceRootRelative converts a validated canonical workspace path to a
// path inside an os.Root. Revalidation alone is not an authorization boundary:
// all actual filesystem operations below must use this rooted descriptor.
func workspaceRootRelative(cp confinedPath, abs string) (string, error) {
	rel, err := filepath.Rel(cp.realRoot, abs)
	if err != nil || (rel != "." && !filepath.IsLocal(rel)) {
		return "", fmt.Errorf("workspace path escapes data root")
	}
	return rel, nil
}

// workspaceOpenParent pins a target's parent before creating/replacing its
// child. Renaming or replacing that directory afterward cannot redirect file
// operations to a different parent. The caller already checked platform-denied
// prefixes with wsResolveConfined and must retain those checks.
func workspaceOpenParent(cp confinedPath, abs string, create bool) (*os.Root, error) {
	root, err := os.OpenRoot(cp.realRoot)
	if err != nil {
		return nil, err
	}
	defer root.Close()
	parentRel, err := workspaceRootRelative(cp, filepath.Dir(abs))
	if err != nil {
		return nil, err
	}
	if create {
		if err := root.MkdirAll(parentRel, 0o755); err != nil {
			return nil, err
		}
	}
	return root.OpenRoot(parentRel)
}

// workspaceAtomicWrite never opens an existing destination for writing.
// A fresh sibling file is written using an exclusive descriptor-relative open,
// then atomically renamed over the destination. An agent replacing the final
// component with a symlink cannot turn this into a privileged write through
// that symlink, and partial writes do not truncate the old file.
func workspaceAtomicWrite(parent *os.Root, name string, src io.Reader) (runErr error) {
	if !filepath.IsLocal(name) || filepath.Base(name) != name {
		return fmt.Errorf("invalid workspace filename")
	}
	perm := os.FileMode(0o644)
	var previous os.FileInfo
	if fi, err := parent.Lstat(name); err == nil {
		if !fi.Mode().IsRegular() {
			return fmt.Errorf("refusing to replace non-regular workspace file")
		}
		// Overwrite must not loosen a file's permissions. Preserve the
		// original owner/group too when the server has that authority.
		previous = fi
		perm = fi.Mode().Perm()
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	var nonce [16]byte
	if _, err := rand.Read(nonce[:]); err != nil {
		return err
	}
	temp := ".artex-write-" + hex.EncodeToString(nonce[:]) + ".tmp"
	out, err := parent.OpenFile(temp, os.O_WRONLY|os.O_CREATE|os.O_EXCL, perm)
	if err != nil {
		return err
	}
	defer func() {
		if runErr != nil {
			_ = parent.Remove(temp)
		}
	}()
	if previous != nil {
		if err := workspacePreserveOwner(out, previous); err != nil {
			_ = out.Close()
			return err
		}
		if err := out.Chmod(perm); err != nil {
			_ = out.Close()
			return err
		}
	}
	if _, err = io.Copy(out, src); err != nil {
		_ = out.Close()
		return err
	}
	if err = out.Close(); err != nil {
		return err
	}
	// A raced symlink is replaced, not followed; the unrelated target is safe.
	return parent.Rename(temp, name)
}

type wsEntry struct {
	Name  string `json:"name"`
	Path  string `json:"path"`
	Dir   bool   `json:"dir"`
	Size  int64  `json:"size"`
	MTime int64  `json:"mtime"` // unix millis
}

// GET /api/workspace/list?path=<rel>
func (s *Server) wsList(w http.ResponseWriter, r *http.Request) {
	cp, ok := s.wsResolveConfined(r.URL.Query().Get("path"))
	if !ok {
		writeErr(w, 400, "invalid path")
		return
	}
	abs := cp.realPath
	rel, err := workspaceRootRelative(cp, abs)
	if err != nil {
		writeErr(w, 400, "invalid path")
		return
	}
	root, err := os.OpenRoot(cp.realRoot)
	if err != nil {
		writeErr(w, 500, safeFSErr(err))
		return
	}
	defer root.Close()
	dir, err := root.Open(rel)
	if err != nil {
		writeErr(w, 404, "path does not exist")
		return
	}
	defer dir.Close()
	fi, err := dir.Stat()
	if err != nil || !fi.IsDir() {
		writeErr(w, 400, "not a directory")
		return
	}
	ents, err := dir.ReadDir(-1)
	if err != nil {
		writeErr(w, 500, safeFSErr(err))
		return
	}
	out := make([]wsEntry, 0, len(ents))
	for _, e := range ents {
		info, err := e.Info()
		if err != nil {
			continue
		}
		out = append(out, wsEntry{
			Name:  e.Name(),
			Path:  s.wsRel(filepath.Join(abs, e.Name())),
			Dir:   e.IsDir(),
			Size:  info.Size(),
			MTime: info.ModTime().UnixMilli(),
		})
	}
	// Directories first, each sorted by name.
	sort.Slice(out, func(i, j int) bool {
		if out[i].Dir != out[j].Dir {
			return out[i].Dir
		}
		return strings.ToLower(out[i].Name) < strings.ToLower(out[j].Name)
	})
	writeJSON(w, 200, map[string]any{"path": s.wsRel(abs), "entries": out})
}

// GET /api/workspace/read?path=<rel> — inline text for view/edit. Binary or oversize
// files return {binary:true}/{too_large:true} with no content (use download instead).
func (s *Server) wsRead(w http.ResponseWriter, r *http.Request) {
	cp, ok := s.wsResolveConfined(r.URL.Query().Get("path"))
	if !ok {
		writeErr(w, 400, "invalid path")
		return
	}
	abs := cp.realPath
	rel, err := workspaceRootRelative(cp, abs)
	if err != nil {
		writeErr(w, 400, "invalid path")
		return
	}
	root, err := os.OpenRoot(cp.realRoot)
	if err != nil {
		writeErr(w, 500, safeFSErr(err))
		return
	}
	defer root.Close()
	file, err := root.Open(rel)
	if err != nil {
		writeErr(w, 404, "file does not exist")
		return
	}
	defer file.Close()
	fi, err := file.Stat()
	if err != nil || !fi.Mode().IsRegular() {
		writeErr(w, 400, "not a regular file")
		return
	}
	if fi.Size() > maxWorkspaceRead {
		writeJSON(w, 200, map[string]any{"path": s.wsRel(abs), "size": fi.Size(), "too_large": true, "binary": true})
		return
	}
	data, err := io.ReadAll(io.LimitReader(file, maxWorkspaceRead+1))
	if err != nil {
		writeErr(w, 500, safeFSErr(err))
		return
	}
	if len(data) > maxWorkspaceRead {
		writeJSON(w, 200, map[string]any{"path": s.wsRel(abs), "size": int64(len(data)), "too_large": true, "binary": true})
		return
	}
	if bytes.IndexByte(data, 0) >= 0 || !utf8.Valid(data) {
		writeJSON(w, 200, map[string]any{"path": s.wsRel(abs), "size": fi.Size(), "binary": true})
		return
	}
	writeJSON(w, 200, map[string]any{"path": s.wsRel(abs), "size": fi.Size(), "binary": false, "content": string(data)})
}

// POST /api/workspace/write  {path, content} — create/overwrite a text file.
func (s *Server) wsWrite(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Path    string `json:"path"`
		Content string `json:"content"`
	}
	if err := decode(w, r, &req); err != nil {
		writeErr(w, 400, err.Error())
		return
	}
	cp, ok := s.wsResolveConfined(req.Path)
	if !ok || cp.realPath == cp.realRoot {
		writeErr(w, 400, "invalid path")
		return
	}
	abs := cp.realPath
	parent, err := workspaceOpenParent(cp, abs, true)
	if err != nil {
		writeErr(w, 400, safeFSErr(err))
		return
	}
	defer parent.Close()
	if err := workspaceAtomicWrite(parent, filepath.Base(abs), strings.NewReader(req.Content)); err != nil {
		writeErr(w, 400, safeFSErr(err))
		return
	}
	writeJSON(w, 200, map[string]any{"ok": true, "path": s.wsRel(abs)})
}

// POST /api/workspace/mkdir  {path}
func (s *Server) wsMkdir(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Path string `json:"path"`
	}
	if err := decode(w, r, &req); err != nil {
		writeErr(w, 400, err.Error())
		return
	}
	cp, ok := s.wsResolveConfined(req.Path)
	if !ok || cp.realPath == cp.realRoot {
		writeErr(w, 400, "invalid path")
		return
	}
	abs := cp.realPath
	rel, err := workspaceRootRelative(cp, abs)
	if err != nil {
		writeErr(w, 400, "invalid path")
		return
	}
	root, err := os.OpenRoot(cp.realRoot)
	if err != nil {
		writeErr(w, 500, safeFSErr(err))
		return
	}
	defer root.Close()
	if err := root.MkdirAll(rel, 0o755); err != nil {
		writeErr(w, 400, safeFSErr(err))
		return
	}
	writeJSON(w, 200, map[string]any{"ok": true, "path": s.wsRel(abs)})
}

// DELETE /api/workspace/delete?path=<rel> — removes a file or a directory tree
// (confined to the work dir; the root itself can't be deleted).
func (s *Server) wsDelete(w http.ResponseWriter, r *http.Request) {
	cp, ok := s.wsResolveConfined(r.URL.Query().Get("path"))
	if !ok {
		writeErr(w, 400, "invalid path")
		return
	}
	if cp.realPath == cp.realRoot {
		writeErr(w, 400, "cannot delete the workspace root directory")
		return
	}
	// entryPath is what RemoveAll removes: a symlink is removed as a link, a
	// directory with everything beneath it.
	if workspaceHoldsDenied(cp.realRoot, cp.entryPath) {
		writeErr(w, 400, "cannot delete a directory that holds platform data (the capture CA, index and blob store)")
		return
	}
	if !cp.exists {
		writeErr(w, 404, "path does not exist")
		return
	}
	// Pin the parent and remove only its leaf. A directory swapped for an
	// external symlink after authorization cannot redirect recursive removal.
	parent, err := workspaceOpenParent(cp, cp.entryPath, false)
	if err != nil {
		writeErr(w, 400, safeFSErr(err))
		return
	}
	defer parent.Close()
	if err := parent.RemoveAll(filepath.Base(cp.entryPath)); err != nil {
		writeErr(w, 500, safeFSErr(err))
		return
	}
	writeJSON(w, 200, map[string]any{"ok": true})
}

// GET /api/workspace/download?path=<rel> — stream a file as an attachment.
func (s *Server) wsDownload(w http.ResponseWriter, r *http.Request) {
	cp, ok := s.wsResolveConfined(r.URL.Query().Get("path"))
	if !ok {
		writeErr(w, 400, "invalid path")
		return
	}
	abs := cp.realPath
	rel, err := workspaceRootRelative(cp, abs)
	if err != nil {
		writeErr(w, 400, "invalid path")
		return
	}
	root, err := os.OpenRoot(cp.realRoot)
	if err != nil {
		writeErr(w, 500, safeFSErr(err))
		return
	}
	defer root.Close()
	file, err := root.Open(rel)
	if err != nil {
		writeErr(w, 404, "file does not exist")
		return
	}
	defer file.Close()
	fi, err := file.Stat()
	if err != nil || !fi.Mode().IsRegular() {
		writeErr(w, 404, "file does not exist")
		return
	}
	name := filepath.Base(cp.entryPath)
	// ServeContent streams from the already-open, confined descriptor and
	// retains HTTP Range/If-Modified-Since behavior without a second path open.
	w.Header().Set("Content-Disposition", "attachment; filename=\""+sanitizeFilename(name)+"\"; filename*=UTF-8''"+url.PathEscape(name))
	http.ServeContent(w, r, name, fi.ModTime(), file)
}

// POST /api/workspace/upload?path=<dir> — multipart form field "file" (one or more).
func (s *Server) wsUpload(w http.ResponseWriter, r *http.Request) {
	dir, ok := s.wsResolveConfined(r.URL.Query().Get("path"))
	if !ok {
		writeErr(w, 400, "invalid path")
		return
	}
	// Pin the upload parent once for the entire request. Workspace agents can
	// rename or replace its path, but not redirect this rooted handle outside.
	dirRel, err := workspaceRootRelative(dir, dir.realPath)
	if err != nil {
		writeErr(w, 400, "invalid path")
		return
	}
	dataRoot, err := os.OpenRoot(dir.realRoot)
	if err != nil {
		writeErr(w, 500, safeFSErr(err))
		return
	}
	defer dataRoot.Close()
	uploadRoot, err := dataRoot.OpenRoot(dirRel)
	if err != nil {
		writeErr(w, 400, "target directory does not exist")
		return
	}
	defer uploadRoot.Close()
	r.Body = http.MaxBytesReader(w, r.Body, maxWorkspaceUpload)
	if err := r.ParseMultipartForm(32 << 20); err != nil {
		writeErr(w, 400, "failed to parse upload or size limit exceeded: "+err.Error())
		return
	}
	defer r.MultipartForm.RemoveAll()
	files := r.MultipartForm.File["file"]
	if len(files) == 0 {
		writeErr(w, 400, "missing upload file (form field file)")
		return
	}
	dirRel = s.wsRel(dir.realPath)
	saved := 0
	for _, hdr := range files {
		name := filepath.Base(hdr.Filename) // strip any path component
		if name == "" || name == "." || name == ".." {
			continue
		}
		destRel := name
		if dirRel != "" {
			destRel = dirRel + "/" + name
		}
		dest, okd := s.wsResolveConfined(destRel)
		if !okd || dest.realPath == dest.realRoot {
			writeErr(w, 400, "invalid path")
			return
		}
		src, err := hdr.Open()
		if err != nil {
			writeErr(w, 500, safeFSErr(err))
			return
		}
		err = workspaceAtomicWrite(uploadRoot, name, src)
		closeErr := src.Close()
		if err == nil {
			err = closeErr
		}
		if err != nil {
			writeErr(w, 400, safeFSErr(err))
			return
		}
		saved++
	}
	writeJSON(w, 200, map[string]any{"uploaded": saved})
}

func saveUpload(hdr *multipart.FileHeader, dest string) error {
	if err := refuseUploadSymlink(dest); err != nil {
		return err
	}
	src, err := hdr.Open()
	if err != nil {
		return err
	}
	defer src.Close()
	out, err := openUploadFileNoFollow(dest)
	if err != nil {
		return err
	}
	defer out.Close()
	_, err = io.Copy(out, src)
	return err
}

// refuseUploadSymlink rejects a destination that is already a symlink. os.Create
// follows one, including a dangling link that Stat reports as missing, so an
// agent that can write the uploads directory could aim the server's write at
// another path. Lstat sees the link itself.
func refuseUploadSymlink(dest string) error {
	fi, err := os.Lstat(dest)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return err
	}
	if fi.Mode()&os.ModeSymlink != 0 {
		return fmt.Errorf("refusing to write through a symlink")
	}
	return nil
}

// sanitizeFilename strips characters unsafe for a Content-Disposition filename token.
func sanitizeFilename(name string) string {
	name = strings.ReplaceAll(name, "\"", "")
	name = strings.ReplaceAll(name, "\\", "")
	name = strings.ReplaceAll(name, "\n", "")
	name = strings.ReplaceAll(name, "\r", "")
	return name
}
