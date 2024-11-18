package main

import (
	"context"
	"fmt"
	"log"
	"os"
	"hash/crc32"
	"strconv"

	secretmanager "cloud.google.com/go/secretmanager/apiv1"
	secretspb "cloud.google.com/go/secretmanager/apiv1/secretmanagerpb"
	kms "cloud.google.com/go/kms/apiv1"
	"cloud.google.com/go/kms/apiv1/kmspb"
	"google.golang.org/protobuf/types/known/wrapperspb"
)

type Config struct {
	ProjectID       string
	SecretID        string
	SecretVersionID string
	SecretEncrypted bool 
	KeyRing         string
	Key             string
}

func main() {
	SecretEncryptedStr := os.Getenv("SECRET_ENCRYPTED")
	if SecretEncryptedStr == "" {
		log.Fatal("Environment variable SECRET_ENCRYPTED is not set.")
	}

	SecretEncrypted, err := strconv.ParseBool(SecretEncryptedStr)
	if err != nil {
		log.Fatalf("Invalid value for SECRET_ENCRYPTED: %v\n", err)
	}

	config := &Config{
		ProjectID:       os.Getenv("PROJECT_ID"),
		SecretID:        os.Getenv("SECRET_ID"),
		SecretVersionID: os.Getenv("SECRET_VERSION_ID"),
		SecretEncrypted: SecretEncrypted,
		KeyRing:         os.Getenv("KEY_RING"),
		Key:             os.Getenv("KEY"),
	}

	if config.ProjectID == "" || config.SecretID == "" || config.SecretVersionID == "" {
		log.Fatal("One or more required environment variables (PROJECT_ID, SECRET_ID, SECRET_VERSION_ID) are not set.")
	}
	
	if config.SecretEncrypted && (config.KeyRing == "" || config.Key == "") {
		log.Fatal("If SECRET_ENCRYPTED is true you need to set additional required environment variables, (KEY_RING, or KEY) are not set.")
	}

	fmt.Printf("ProjectID is: %s\n", config.ProjectID)
	fmt.Printf("SecretID is: %s\n", config.SecretID)
	fmt.Printf("SecretVersionID is: %s\n", config.SecretVersionID)
	fmt.Printf("SecretEncrypted is: %t\n", config.SecretEncrypted)
	fmt.Printf("KeyRing is: %s\n", config.KeyRing)
	fmt.Printf("Key is: %s\n", config.Key)

	ctx := context.Background()
	client, err := secretmanager.NewClient(ctx)
	if err != nil {
		log.Fatalf("failed to setup client: %v", err)
	}
	defer client.Close()

	SecretManagerName := fmt.Sprintf("projects/%s/secrets/%s/versions/%s", config.ProjectID, config.SecretID, config.SecretVersionID)
	fmt.Printf("constructed SecretManagerName is: %s\n", SecretManagerName)

	SecretManagerValue, err := accessSecretVersion(ctx, client, SecretManagerName)
	if err != nil {
		fmt.Printf("Failed to access secret version: %v\n", err)
		return
	}

	fmt.Printf("secret manager value is: %s\n", SecretManagerValue)

	if config.SecretEncrypted {
		decryptedSecret, err := decryptSymmetric(ctx, config, []byte(SecretManagerValue))
		if err != nil {
			fmt.Printf("Failed to decrypt the secret: %v\n", err)
			return
		}
		fmt.Printf("decrypted secret value is: %s\n", decryptedSecret)
	} else {
		fmt.Printf("Secret encryption is disabled. Using the raw secret manager value.\n")
	}
}

func accessSecretVersion(ctx context.Context, client *secretmanager.Client, name string) (string, error) {
	req := &secretspb.AccessSecretVersionRequest{
		Name: name,
	}

	resp, err := client.AccessSecretVersion(ctx, req)
	if err != nil {
		return "", fmt.Errorf("failed to access secret version: %w", err)
	}
	return string(resp.Payload.Data), nil
}

func decryptSymmetric(ctx context.Context, config *Config, ciphertext []byte) (string, error) {
	name := fmt.Sprintf("projects/%s/locations/global/keyRings/%s/cryptoKeys/%s", config.ProjectID, config.KeyRing, config.Key)

	client, err := kms.NewKeyManagementClient(ctx)
	if err != nil {
		return "", fmt.Errorf("failed to create kms client: %w", err)
	}
	defer client.Close()

	crc32c := func(data []byte) uint32 {
		t := crc32.MakeTable(crc32.Castagnoli)
		return crc32.Checksum(data, t)
	}
	ciphertextCRC32C := crc32c(ciphertext)

	req := &kmspb.DecryptRequest{
		Name:             name,
		Ciphertext:       ciphertext,
		CiphertextCrc32C: wrapperspb.Int64(int64(ciphertextCRC32C)),
	}

	result, err := client.Decrypt(ctx, req)
	if err != nil {
		return "", fmt.Errorf("failed to decrypt ciphertext: %w", err)
	}

	if int64(crc32c(result.Plaintext)) != result.PlaintextCrc32C.Value {
		return "", fmt.Errorf("decrypt: response corrupted in-transit")
	}

	return string(result.Plaintext), nil
}
