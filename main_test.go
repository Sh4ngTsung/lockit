package main

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"io"
	"os"
	"testing"
)

func generateKey() []byte {
	key := make([]byte, 32)
	rand.Read(key)
	return key
}

// fileHash calculates the SHA-256 hash of a file to verify its integrity.
func fileHash(path string) (string, error) {
	file, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer file.Close()

	hasher := sha256.New()
	if _, err := io.Copy(hasher, file); err != nil {
		return "", err
	}
	return hex.EncodeToString(hasher.Sum(nil)), nil
}

// Verifies that the file was encrypted and decrypted correctly
func TestEncryptDecrypt(t *testing.T) {
	tempFile := "testfile.txt"
	encFile := tempFile + ".cryptsec"
	testContent := []byte("Encryption and decryption test.")
	key := generateKey()

	if err := os.WriteFile(tempFile, testContent, 0644); err != nil {
		t.Fatalf("Failed to create test file: %v", err)
	}

	hashOriginal, _ := fileHash(tempFile)

	if err := encryptFile(tempFile, key, 3); err != nil {
		t.Fatalf("Error encrypting: %v", err)
	}

	if _, err := os.Stat(tempFile); !os.IsNotExist(err) {
		t.Fatalf("Original file was not removed after encryption")
	}

	if _, err := os.Stat(encFile); os.IsNotExist(err) {
		t.Fatalf("Encrypted file not created")
	}

	if err := decryptFile(encFile, key, 3); err != nil {
		t.Fatalf("Error decrypting: %v", err)
	}

	if _, err := os.Stat(encFile); !os.IsNotExist(err) {
		t.Fatalf("Encrypted file not removed after decryption")
	}

	hashDecrypted, _ := fileHash(tempFile)

	// Verify file integrity
	if hashOriginal != hashDecrypted {
		t.Fatalf("Decrypted file is not identical to the original")
	}

	os.Remove(tempFile)
}

// Checks if decryption fails when using an incorrect key
func TestInvalidKeyDecryption(t *testing.T) {
	tempFile := "test_invalid_key.txt"
	encFile := tempFile + ".cryptsec"
	testContent := []byte("Test content for incorrect key.")
	key := generateKey()
	wrongKey := generateKey()

	if err := os.WriteFile(tempFile, testContent, 0644); err != nil {
		t.Fatalf("Failed to create test file: %v", err)
	}

	if err := encryptFile(tempFile, key, 3); err != nil {
		t.Fatalf("Error encrypting: %v", err)
	}

	if err := decryptFile(encFile, wrongKey, 3); err == nil {
		t.Fatalf("Decryption with incorrect key should fail, but it didnt")
	}

	os.Remove(encFile)
}

// Checks that secure overwrite works correctly
func TestSecureOverwrite(t *testing.T) {
	tempFile := "test_overwrite.txt"
	testContent := []byte("Sensitive data that must be securely erased.")

	if err := os.WriteFile(tempFile, testContent, 0644); err != nil {
		t.Fatalf("Failed to create test file: %v", err)
	}

	if err := overwriteAndRemove(tempFile, 3); err != nil {
		t.Fatalf("Failed to overwrite and remove file: %v", err)
	}

	if _, err := os.Stat(tempFile); !os.IsNotExist(err) {
		t.Fatalf("File not removed after secure overwrite")
	}
}
