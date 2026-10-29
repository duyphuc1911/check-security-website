// Package securecoding provides secure coding examples.
package securecoding

import (
	"bytes"
	"context"
	"database/sql"
	"fmt"
	"html/template"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
)

// SQL injection.
func FindUserName(ctx context.Context, db *sql.DB, userID int64) (string, error) {
	var displayName string
	err := db.QueryRowContext(
		ctx,
		"SELECT display_name FROM users WHERE id = $1",
		userID,
	).Scan(&displayName)
	if err != nil {
		return "", fmt.Errorf("query user: %w", err)
	}
	return displayName, nil
}

// XSS.
func SearchPage(userInput string) (string, error) {
	const page = `<p class="search-result">{{.}}</p>`
	parsed, err := template.New("search").Parse(page)
	if err != nil {
		return "", fmt.Errorf("parse template: %w", err)
	}
	var output bytes.Buffer
	if err := parsed.Execute(&output, userInput); err != nil {
		return "", fmt.Errorf("render search page: %w", err)
	}
	return output.String(), nil
}

// Command injection.
func GitStatus(parent context.Context) ([]byte, error) {
	ctx, cancel := context.WithTimeout(parent, 10*time.Second)
	defer cancel()

	command := exec.CommandContext(ctx, "git", "status", "--short")
	output, err := command.Output()
	if err != nil {
		return nil, fmt.Errorf("git status failed: %w", err)
	}
	return output, nil
}

// Path traversal.
func ReadUpload(uploadRoot, requestedName string) ([]byte, error) {
	root, err := filepath.EvalSymlinks(uploadRoot)
	if err != nil {
		return nil, fmt.Errorf("resolve upload root: %w", err)
	}
	root, err = filepath.Abs(root)
	if err != nil {
		return nil, fmt.Errorf("make upload root absolute: %w", err)
	}

	candidate, err := filepath.EvalSymlinks(filepath.Join(root, requestedName))
	if err != nil {
		return nil, fmt.Errorf("resolve requested upload: %w", err)
	}
	candidate, err = filepath.Abs(candidate)
	if err != nil {
		return nil, fmt.Errorf("make requested upload absolute: %w", err)
	}
	relative, err := filepath.Rel(root, candidate)
	if err != nil {
		return nil, fmt.Errorf("check upload containment: %w", err)
	}
	if relative == ".." || filepath.IsAbs(relative) ||
		strings.HasPrefix(relative, ".."+string(filepath.Separator)) {
		return nil, fmt.Errorf("requested file is outside the upload directory")
	}
	return os.ReadFile(candidate)
}
