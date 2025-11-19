package main

import (
	"context"
	"crypto"
	"crypto/x509"
	"fmt"
	"path/filepath"

	azvlib "github.com/j358/azv_pkcs11/lib"
)

//azvlib "github.com/j358/azv_pkcs11/lib"

var signer azvlib.AzvSigner

func certFromAzv(_ context.Context, path string) (*x509.Certificate, error) {
	var err error
	// split path into vault and cert name
	vault, keyName := filepath.Split(path)
	if len(vault) <= 5 || len(keyName) <= 5 {
		return nil, fmt.Errorf("invalid path %q, must be in format vault/cert, minimum length is 6 for each", path)
	}

	if signer.VaultName != vault {
		err = signer.CreateSigner(vault)
		if err != nil {
			return nil, fmt.Errorf("failed to create signer for vault %q: %w", vault, err)
		}
	}

	if signer.KeyName != keyName {
		err = signer.SetKey(keyName)
		if err != nil {
			return nil, fmt.Errorf("failed to set key for key %q: %w", keyName, err)
		}
	}

	err = signer.GetCertForKey()
	if err != nil {
		return nil, fmt.Errorf("failed to get cert for key %q: %w", keyName, err)
	}

	bytes, err := signer.GetCertBytes()
	if err != nil {
		return nil, fmt.Errorf("failed to get cert bytes for cert %q: %w", keyName, err)
	}
	if bytes == nil {
		return nil, fmt.Errorf("no cert bytes found for cert %q", keyName)
	}

	return x509.ParseCertificate(bytes)
}

func signerFromAzv(_ context.Context, path string) (crypto.Signer, error) {
	var err error
	// split path into vault and cert name
	vault, keyName := filepath.Split(path)
	if len(vault) <= 5 || len(keyName) <= 5 {
		return nil, fmt.Errorf("invalid path %q, must be in format vault/cert, minimum length is 6 for each", path)
	}

	if signer.VaultName != vault {
		err = signer.CreateSigner(vault)
		if err != nil {
			return nil, fmt.Errorf("failed to create signer for vault %q: %w", vault, err)
		}
	}

	if signer.KeyName != keyName {
		err = signer.SetKey(keyName)
		if err != nil {
			return nil, fmt.Errorf("failed to set key for key %q: %w", keyName, err)
		}
	}

	return &signer, nil
}
