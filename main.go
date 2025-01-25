package main

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"golang.org/x/crypto/argon2"
	"golang.org/x/term"
)

type Config struct {
	Encrypt       bool
	Decrypt       bool
	Directory     string
	Threads       int
	SingleFile    string
	UseMultithread bool
	Passes        int
}

func main() {
	config := parseFlags()
	var key []byte
	if config.Encrypt {
		key = getKeyFromUserForEncryption()
	} else if config.Decrypt {
		key = getKeyFromUserForDecryption()
	} else {
		fmt.Println("No valid operation specified. Use -h for help.")
		os.Exit(1)
	}

	if config.SingleFile != "" {
		if err := processSingleFile(config.SingleFile, key, config.Encrypt, config.Decrypt, config.Passes); err != nil {
			fmt.Printf("Error processing file: %v\n", err)
		}
	} else if config.Directory != "" {
		processDirectory(config.Directory, key, config.Encrypt, config.Decrypt, config.UseMultithread, config.Threads, config.Passes)
	} else {
		fmt.Println("No valid input provided. Use -h for help.")
		os.Exit(1)
	}
}

func parseFlags() Config {
	encrypt := flag.Bool("e", false, "Encrypt files")
	decrypt := flag.Bool("d", false, "Decrypt files")
	directory := flag.String("r", "", "Directory to process")
	singleFile := flag.String("f", "", "Single file to process")
	threads := flag.Int("t", 30, "Number of threads for multithreading")
	passes := flag.Int("p", 0, "Number of overwrite passes for secure deletion (0 for normal deletion)")

	flag.Parse()

	if *encrypt && *decrypt {
		fmt.Println("Cannot use -e and -d together. Exiting.")
		os.Exit(1)
	}

	useMultithread := *threads > 1

	return Config{
		Encrypt:       *encrypt,
		Decrypt:       *decrypt,
		Directory:     *directory,
		Threads:       *threads,
		SingleFile:    *singleFile,
		UseMultithread: useMultithread,
		Passes:        *passes,
	}
}

func getKeyFromUserForEncryption() []byte {
	fmt.Print("Enter encryption key: ")
	key1, _ := term.ReadPassword(int(os.Stdin.Fd()))
	fmt.Println()

	fmt.Print("Confirm encryption key: ")
	key2, _ := term.ReadPassword(int(os.Stdin.Fd()))
	fmt.Println()

	if !bytes.Equal(key1, key2) {
		fmt.Println("Keys do not match. Exiting.")
		os.Exit(1)
	}

	// Derive a 32-byte key from the user-supplied key
	derivedKey := deriveKey(key1)

	defer zeroize(key1)
	defer zeroize(key2)
	return derivedKey
}

func getKeyFromUserForDecryption() []byte {
	fmt.Print("Enter decryption key: ")
	key, _ := term.ReadPassword(int(os.Stdin.Fd()))
	fmt.Println()

	derivedKey := deriveKey(key)

	defer zeroize(key)
	return derivedKey
}

func deriveKey(inputKey []byte) []byte {
	// Argon2 Settings
	salt := []byte("random_salt")
	iterations := uint32(16)
	memory := uint32(64 * 1024)
	parallelism := uint8(4)

	key := argon2.Key(inputKey, salt, iterations, memory, parallelism, 32)
	return key
}

func processSingleFile(filePath string, key []byte, encrypt, decrypt bool, passes int) error {
	if encrypt {
		return encryptFile(filePath, key, passes)
	} else if decrypt {
		return decryptFile(filePath, key, passes)
	}
	return errors.New("invalid operation: must specify -e or -d")
}

func processDirectory(directory string, key []byte, encrypt, decrypt, useMultithread bool, threads int, passes int) {
	var wg sync.WaitGroup
	fileChan := make(chan string, threads)

	fileCount := 0
	err := filepath.Walk(directory, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if !info.IsDir() {
			fileCount++
		}
		return nil
	})

	if err != nil {
		fmt.Printf("Error walking directory: %v\n", err)
		return
	}

	// Limit the number of threads to the number of files if necessary
	if threads > fileCount {
		threads = fileCount
	}

	if useMultithread {
		for i := 0; i < threads; i++ {
			wg.Add(1)
			go func() {
				for file := range fileChan {
					if encrypt {
						if err := encryptFile(file, key, passes); err != nil {
							fmt.Printf("Error encrypting file %s: %v\n", file, err)
						}
					} else if decrypt {
						if err := decryptFile(file, key, passes); err != nil {
							fmt.Printf("Error decrypting file %s: %v\n", file, err)
						}
					}
				}
				wg.Done()
			}()
		}
	}

	err = filepath.Walk(directory, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if !info.IsDir() {
			fileChan <- path
		}
		return nil
	})

	if err != nil {
		fmt.Printf("Error walking directory: %v\n", err)
	}

	// Close the channel and wait for threads to complete
	if useMultithread {
		close(fileChan)
		wg.Wait()
	}
}

func overwriteAndRemove(filePath string, passes int) error {
	if passes <= 0 {
		return os.Remove(filePath)
	}

	fileInfo, err := os.Stat(filePath)
	if err != nil {
		return fmt.Errorf("failed to stat file: %w", err)
	}

	size := fileInfo.Size()
	file, err := os.OpenFile(filePath, os.O_WRONLY, 0644)
	if err != nil {
		return fmt.Errorf("failed to open file for overwriting: %w", err)
	}
	defer file.Close()

	buffer := make([]byte, 4096)
	for p := 0; p < passes; p++ {
		var fillByte byte
		if p%3 == 0 {
			fillByte = 0x00
		} else if p%3 == 1 {
			fillByte = 0xFF
		} else {
			if _, err := rand.Read(buffer); err != nil {
				return fmt.Errorf("failed to generate random data: %w", err)
			}
		}

		for written := int64(0); written < size; written += int64(len(buffer)) {
			if p%3 != 2 {
				for i := range buffer {
					buffer[i] = fillByte
				}
			}
			if _, err := file.WriteAt(buffer, written); err != nil {
				return fmt.Errorf("failed to overwrite file: %w", err)
			}
		}
	}

	file.Close()
	return os.Remove(filePath)
}


func encryptFile(filePath string, key []byte, passes int) error {
	if strings.HasSuffix(filePath, ".cryptsec") {
		fmt.Printf("Skipping already encrypted file: %s\n", filePath)
		return nil
	}

	inputFile, err := os.Open(filePath)
	if err != nil {
		return fmt.Errorf("failed to open file for encryption: %w", err)
	}
	defer inputFile.Close()

	outputPath := filePath + ".cryptsec"
	outputFile, err := os.Create(outputPath)
	if err != nil {
		return fmt.Errorf("failed to create encrypted file: %w", err)
	}
	defer outputFile.Close()

	block, err := aes.NewCipher(key)
	if err != nil {
		return fmt.Errorf("failed to create AES cipher: %w", err)
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return fmt.Errorf("failed to create GCM cipher: %w", err)
	}

	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return fmt.Errorf("failed to generate nonce: %w", err)
	}

	if _, err := outputFile.Write(nonce); err != nil {
		return fmt.Errorf("failed to write nonce: %w", err)
	}

	buffer := make([]byte, 4096)
	for {
		n, err := inputFile.Read(buffer)
		if err == io.EOF {
			break
		}
		if err != nil {
			return fmt.Errorf("failed to read file: %w", err)
		}

		ciphertext := gcm.Seal(nil, nonce, buffer[:n], nil)
		if _, err := outputFile.Write(ciphertext); err != nil {
			return fmt.Errorf("failed to write encrypted data: %w", err)
		}
	}

	inputFile.Close()
	return overwriteAndRemove(filePath, passes)
}

func decryptFile(filePath string, key []byte, passes int) error {
	if !strings.HasSuffix(filePath, ".cryptsec") {
		return fmt.Errorf("file %s is not encrypted", filePath)
	}

	inputFile, err := os.Open(filePath)
	if err != nil {
		return fmt.Errorf("failed to open encrypted file: %w", err)
	}
	defer inputFile.Close()

	block, err := aes.NewCipher(key)
	if err != nil {
		return fmt.Errorf("failed to create AES cipher: %w", err)
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return fmt.Errorf("failed to create GCM cipher: %w", err)
	}

	nonceSize := gcm.NonceSize()
	nonce := make([]byte, nonceSize)

	if _, err := io.ReadFull(inputFile, nonce); err != nil {
		return fmt.Errorf("failed to read nonce: %w", err)
	}

	outputPath := strings.TrimSuffix(filePath, ".cryptsec")
	outputFile, err := os.Create(outputPath)
	if err != nil {
		return fmt.Errorf("failed to create decrypted file: %w", err)
	}
	defer outputFile.Close()

	buffer := make([]byte, 4096+gcm.Overhead())
	for {
		n, err := inputFile.Read(buffer)
		if err == io.EOF {
			break
		}
		if err != nil {
			return fmt.Errorf("failed to read encrypted data: %w", err)
		}

		plaintext, err := gcm.Open(nil, nonce, buffer[:n], nil)
		if err != nil {
			return fmt.Errorf("failed to decrypt data: %w", err)
		}

		if _, err := outputFile.Write(plaintext); err != nil {
			return fmt.Errorf("failed to write decrypted data: %w", err)
		}
	}

	inputFile.Close()
	if err := os.Remove(filePath); err != nil {
		return fmt.Errorf("failed to remove encrypted file: %w", err)
	}

	return nil
}

func zeroize(data []byte) {
	for i := range data {
		data[i] = 0
	}
}
