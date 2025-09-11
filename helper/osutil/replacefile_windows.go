//go:build windows

package osutil

import (
	"os"
	"syscall"
	"unsafe"

	"golang.org/x/sys/windows"
)

var (
	// See https://learn.microsoft.com/en-us/windows/win32/api/winbase/nf-winbase-movefileexw
	modkernel32 = windows.NewLazySystemDLL("kernel32.dll")
	moveFileExW = modkernel32.NewProc("MoveFileExW")
)

// ReplaceFile atomically replaces the destination file or directory with the
// source. It is guaranteed to either replace the target file entirely, or not
// change either file.
func ReplaceFile(oldpath, newpath string) error {
	src, err := syscall.UTF16PtrFromString(oldpath)
	if err != nil {
		return &os.LinkError{Op: "rename", Old: oldpath, New: newpath, Err: err}
	}

	dest, err := syscall.UTF16PtrFromString(newpath)
	if err != nil {
		return &os.LinkError{Op: "rename", Old: oldpath, New: newpath, Err: err}
	}

	r1, _, errno := syscall.SyscallN(moveFileExW.Addr(),
		uintptr(unsafe.Pointer(src)), uintptr(unsafe.Pointer(dest)),
		uintptr(0x1 /* MOVEFILE_REPLACE_EXISTING */ |0x8 /* MOVEFILE_WRITE_THROUGH */))

	switch {
	case r1 != 0:
		return nil
	case errno == 0:
		err = syscall.EINVAL
	default:
		err = errno
	}

	return &os.LinkError{Op: "rename", Old: oldpath, New: newpath, Err: err}
}
