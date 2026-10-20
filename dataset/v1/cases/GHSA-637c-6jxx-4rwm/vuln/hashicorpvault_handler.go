// Source: https://github.com/kedacore/keda
// Ref: 2963aa3d3ba073a01f56865a557563ba40a2174c Path: pkg/scaling/resolver/hashicorpvault_handler.go
// Excerpted and modified from https://github.com/kedacore/keda@2963aa3d3ba073a01f56865a557563ba40a2174c on 2026-10-20
// License: Apache-2.0, see licenses/kedacore__keda/LICENSE
// Copyright 2021 The KEDA Authors
import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/go-logr/logr"
	vaultapi "github.com/hashicorp/vault/api"
// ... lines 27-29 omitted ...
)

const (
	serviceAccountTokenFile = "/var/run/secrets/kubernetes.io/serviceaccount/token"
)

// HashicorpVaultHandler is a specification of HashiCorp Vault
// ... lines 37-54 omitted ...
func (vh *HashicorpVaultHandler) Initialize(logger logr.Logger) error {
	config := vaultapi.DefaultConfig()
	client, err := vaultapi.NewClient(config)
	if err != nil {
		return err
	}

	err = client.SetAddress(vh.vault.Address)
	if err != nil {
		return err
	}

	if len(vh.vault.Namespace) > 0 {
		client.SetNamespace(vh.vault.Namespace)
	}

	token, err := vh.token(client)
	if err != nil {
		return err
	}

	if len(token) > 0 {
		client.SetToken(token)
	}

	lookup, err := client.Auth().Token().LookupSelf()
	// If token is not valid so get out of here early
	if err != nil {
		return err
	}

	vh.client = client

	if renew, ok := lookup.Data["renewable"].(bool); ok && renew {
		vh.stopCh = make(chan struct{})
		go vh.renewToken(logger)
	}

	return nil
}
// ... lines 95-96 omitted ...
func (vh *HashicorpVaultHandler) token(client *vaultapi.Client) (string, error) {
	var token string
	var jwt []byte
	var err error

	switch vh.vault.Authentication {
	case kedav1alpha1.VaultAuthenticationToken:
		// Got token from VAULT_TOKEN env variable
		switch {
		case len(client.Token()) > 0:
			break
		case len(vh.vault.Credential.Token) > 0:
			token = vh.vault.Credential.Token
		default:
			return token, errors.New("could not get Vault token")
		}
	case kedav1alpha1.VaultAuthenticationKubernetes:
		if len(vh.vault.Mount) == 0 {
			return token, errors.New("auth mount not in config")
		}

		if len(vh.vault.Role) == 0 {
			return token, errors.New("k8s role not in config")
		}

		if vh.vault.Credential == nil {
			defaultCred := kedav1alpha1.Credential{
				ServiceAccount: serviceAccountTokenFile,
			}
			vh.vault.Credential = &defaultCred
		}

		if vh.vault.Credential.ServiceAccountName == "" && vh.vault.Credential.ServiceAccount == "" {
			return token, errors.New("k8s SA file not in config or serviceAccountName not supplied")
		}

		if vh.vault.Credential.ServiceAccountName != "" {
			jwt = []byte(GenerateBoundServiceAccountToken(context.Background(), vh.vault.Credential.ServiceAccountName, vh.namespace, vh.acs))
		} else if len(vh.vault.Credential.ServiceAccount) != 0 {
			// Get the JWT from POD
			jwt, err = readKubernetesServiceAccountProjectedToken(vh.vault.Credential.ServiceAccount)
			if err != nil {
				return token, err
			}
		}

		data := map[string]any{"jwt": string(jwt), "role": vh.vault.Role}
		secret, err := client.Logical().Write(fmt.Sprintf("auth/%s/login", vh.vault.Mount), data)
		if err != nil {
			return token, err
		}
		token = secret.Auth.ClientToken

	default:
		return token, fmt.Errorf("vault auth method %s is not supported", vh.vault.Authentication)
	}

	return token, nil
}

// renewToken takes charge of renewing the vault token
