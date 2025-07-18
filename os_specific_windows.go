// go:build windows

package gosnowflake

import (
	"errors"
	"fmt"
	"os"
	"syscall"
	"unsafe"

	"golang.org/x/sys/windows"
)

func provideFileOwner(file *os.File) (uint32, error) {
	return 0, errors.New("provideFileOwner is unsupported on windows")
}

func getFileContents(filePath string, expectedPerm os.FileMode) ([]byte, error) {
	fileContents, err := os.ReadFile(filePath)
	if err != nil {
		return nil, err
	}
	return fileContents, nil
}

var (
	modShell32               = syscall.NewLazyDLL("Shell32.dll")
	procSHGetKnownFolderPath = modShell32.NewProc("SHGetKnownFolderPath")

	modOle32          = syscall.NewLazyDLL("Ole32.dll")
	procCoTaskMemFree = modOle32.NewProc("CoTaskMemFree")

	// Known folder IDs for Windows [1].
	//
	// {F1B32785-6FBA-4FCF-9D55-7B8E7F157091}
	FOLDERID_LocalAppData = syscall.GUID{Data1: 0xF1B32785, Data2: 0x6FBA, Data3: 0x4FCF, Data4: [8]byte{0x9D, 0x55, 0x7B, 0x8E, 0x7F, 0x15, 0x70, 0x91}}

	// Common HRESULT values for Windows [2].
	S_OK         = 0x0
	E_FAIL       = 0x80004005
	E_INVALIDARG = 0x80070057
)

// Return the path to a known folder for Windows [3].
//
// The folderId argument should be the GUID for the known folder path [1].
//
// [1] https://learn.microsoft.com/en-us/windows/win32/shell/knownfolderid
// [2] https://learn.microsoft.com/en-us/windows/win32/seccrypto/common-hresult-values
// [3] https://learn.microsoft.com/en-us/windows/win32/api/shlobj_core/nf-shlobj_core-shgetknownfolderpath
func getKnownFolderPath(folderId syscall.GUID) (string, error) {
	// Get the path to local app data folder
	var raw *uint16
	ret, _, _ := procSHGetKnownFolderPath.Call(
		uintptr(unsafe.Pointer(&folderId)),
		0,
		0,
		uintptr(unsafe.Pointer(&raw)))
	if ret != uintptr(S_OK) {
		if ret == uintptr(E_FAIL) {
			return "", fmt.Errorf("E_FAIL")
		}
		if ret == uintptr(E_INVALIDARG) {
			return "", fmt.Errorf("E_INVALIDARG: %v", folderId)
		}
		return "", fmt.Errorf("unknown error: 0x%x", uintptr(ret))
	}

	// Defer freeing memory since this API call is managed
	defer procCoTaskMemFree.Call(uintptr(unsafe.Pointer(raw)))

	// Convert UTF-16 to a Go string
	return syscall.UTF16ToString((*[1 << 16]uint16)(unsafe.Pointer(raw))[:]), nil
}

func cryptProtectData(data []byte) ([]byte, error) {
	if len(data) == 0 {
		return nil, nil
	}
	plaintext := windows.DataBlob{
		Size: uint32(len(data)),
		Data: &data[0],
	}
	ciphertext := windows.DataBlob{
		Size: 0,
		Data: nil,
	}
	// https://learn.microsoft.com/en-us/windows/win32/api/dpapi/nf-dpapi-cryptprotectdata
	err := windows.CryptProtectData(&plaintext, nil, nil, 0, nil, windows.CRYPTPROTECT_UI_FORBIDDEN, &ciphertext)
	if err != nil {
		return nil, err
	}
	defer windows.LocalFree(windows.Handle(unsafe.Pointer(ciphertext.Data)))
	slice := unsafe.Slice(ciphertext.Data, ciphertext.Size)
	result := make([]byte, len(slice))
	copy(result, slice)
	return result, nil
}

func cryptUnprotectData(data []byte) ([]byte, error) {
	if len(data) == 0 {
		return nil, nil
	}
	ciphertext := windows.DataBlob{
		Size: uint32(len(data)),
		Data: &data[0],
	}
	plaintext := windows.DataBlob{
		Size: 0,
		Data: nil,
	}
	// https://learn.microsoft.com/en-us/windows/win32/api/dpapi/nf-dpapi-cryptunprotectdata
	err := windows.CryptUnprotectData(&ciphertext, nil, nil, 0, nil, windows.CRYPTPROTECT_UI_FORBIDDEN, &plaintext)
	if err != nil {
		return nil, err
	}
	defer windows.LocalFree(windows.Handle(unsafe.Pointer(plaintext.Data)))
	slice := unsafe.Slice(plaintext.Data, plaintext.Size)
	result := make([]byte, len(slice))
	copy(result, slice)
	return result, nil
}
