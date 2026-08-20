package homedir

import (
	"bytes"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync"
)

var (
	cache     string
	cacheLock sync.Mutex
)

// Dir returns the home directory for the executing user.
//
// This uses an OS-specific method for discovering the home directory.
// An error is returned if a home directory cannot be detected.
func Dir() (string, error) {
	cacheLock.Lock()
	defer cacheLock.Unlock()

	if cache != "" {
		return cache, nil
	}

	var err error
	switch runtime.GOOS {
	case "windows":
		cache, err = dirWindows()
	default:
		// Unix-like system, so just assume Unix.
		cache, err = dirUnix()
	}

	if err != nil {
		return "", err
	}

	return cache, nil
}

// Expand expands the path to include the home directory if the path is prefixed
// with `~`. If it isn't prefixed with `~`, the path is returned as-is.
func Expand(path string) (string, error) {
	if len(path) == 0 {
		return path, nil
	}

	if path[0] != '~' {
		return path, nil
	}

	if len(path) > 1 && path[1] != '/' && path[1] != '\\' {
		return "", errors.New("cannot expand user-specific home directory")
	}

	dir, err := Dir()
	if err != nil {
		return "", err
	}

	return filepath.Join(dir, path[1:]), nil
}

func dirUnix() (string, error) {
	homeEnv := "HOME"
	if runtime.GOOS == "plan9" {
		// On plan9, env vars are lowercase.
		homeEnv = "home"
	}

	// First prefer the HOME environmental variable.
	if home := os.Getenv(homeEnv); home != "" {
		return home, nil
	}

	var stdout bytes.Buffer

	// If that fails, try OS specific commands.
	switch runtime.GOOS {
	case "darwin":
		cmd := exec.Command("sh", "-c", `dscl -q . -read /Users/"$(whoami)" NFSHomeDirectory`)
		cmd.Stdout = &stdout
		if err := cmd.Run(); err != nil {
			break
		}
		if result := strings.TrimSpace(strings.TrimPrefix(stdout.String(), "NFSHomeDirectory: ")); result != "" {
			return result, nil
		}
	default:
		cmd := exec.Command("getent", "passwd", strconv.Itoa(os.Getuid()))
		cmd.Stdout = &stdout
		if err := cmd.Run(); err != nil {
			break
		}
		if passwd := strings.TrimSpace(stdout.String()); passwd != "" {
			// username:password:uid:gid:gecos:home:shell
			passwdParts := strings.SplitN(passwd, ":", 7)
			if len(passwdParts) > 5 {
				return passwdParts[5], nil
			}
		}
	}

	// If all else fails, try the shell.
	stdout.Reset()
	cmd := exec.Command("sh", "-c", "cd && pwd")
	cmd.Stdout = &stdout
	if err := cmd.Run(); err != nil {
		return "", err
	}

	if result := strings.TrimSpace(stdout.String()); result != "" {
		return result, nil
	}

	return "", errors.New("could not determine home directory")
}

func dirWindows() (string, error) {
	// First prefer the HOME environmental variable.
	if home := os.Getenv("HOME"); home != "" {
		return home, nil
	}

	// Prefer standard environment variable USERPROFILE.
	if home := os.Getenv("USERPROFILE"); home != "" {
		return home, nil
	}

	if drive, path := os.Getenv("HOMEDRIVE"), os.Getenv("HOMEPATH"); drive != "" && path != "" {
		return drive + path, nil
	}

	return "", errors.New("HOME, USERPROFILE and HOMEDRIVE or HOMEPATH are blank")
}
