// Source: https://github.com/kedacore/keda
// Ref: 1e21cc798dedd079e696cdb45388eddc5e18365d Path: pkg/scaling/resolver/hashicorpvault_handler.go
// Excerpted and modified from https://github.com/kedacore/keda@1e21cc798dedd079e696cdb45388eddc5e18365d on 2026-10-20
// License: Apache-2.0, see licenses/kedacore__keda/LICENSE
// Copyright 2021 The KEDA Authors
import (
	"context"
	"errors"
	"fmt"
	"net/url"
	"strings"

	"github.com/go-logr/logr"
	vaultapi "github.com/hashicorp/vault/api"
// ... lines 28-30 omitted ...
)

const (
	// serviceAccountTokenFile is the operator's Kubernetes API token path, used only for the legacy Vault authentication fallback. Remove when legacy mode is retired.
	serviceAccountTokenFile             = "/var/run/secrets/kubernetes.io/serviceaccount/token"
	DefaultVaultKubernetesAuthTokenFile = "/var/run/secrets/keda-vault/token"
)

// HashicorpVaultHandler is a specification of HashiCorp Vault
// ... lines 40-57 omitted ...
func (vh *HashicorpVaultHandler) Initialize(logger logr.Logger) error {
	if err := vh.validateAddress(logger); err != nil {
		return err
	}

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

	token, err := vh.token(client, logger)
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

// token Extract a vault token from the Authentication method
func (vh *HashicorpVaultHandler) token(client *vaultapi.Client, logger logr.Logger) (string, error) {
	var token string

	switch vh.vault.Authentication {
	case kedav1alpha1.VaultAuthenticationToken:
		// Got token from VAULT_TOKEN env variable
		switch {
		case len(client.Token()) > 0:
			break
		case vh.vault.Credential != nil && len(vh.vault.Credential.Token) > 0:
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

		jwt, err := vh.kubernetesToken(context.Background())
		if err != nil {
			return token, err
		}
		if globalConfig.IsLegacyServiceAccountTokenMode() {
			logger.Info("Warning: Vault Kubernetes authentication is using a legacy service account token; a leaked token may grant Kubernetes API access. Configure approved audiences and --service-account-token-mode=enforce-audience", "vaultOrigin", vh.origin())
		}

		data := map[string]any{"jwt": string(jwt), "role": vh.vault.Role}
		secret, err := client.Logical().Write(fmt.Sprintf("auth/%s/login", vh.vault.Mount), data)
		if err != nil {
			return token, err
		}
		if secret == nil || secret.Auth == nil || secret.Auth.ClientToken == "" {
			return token, errors.New("vault Kubernetes login returned no client token")
		}
		token = secret.Auth.ClientToken

	default:
		return token, fmt.Errorf("vault auth method %s is not supported", vh.vault.Authentication)
	}

	return token, nil
}

// kubernetesToken mints a named-SA token or reads a token file on each login.
func (vh *HashicorpVaultHandler) kubernetesToken(ctx context.Context) ([]byte, error) {
	legacy := globalConfig.IsLegacyServiceAccountTokenMode()
	path := globalConfig.VaultKubernetesAuthTokenFile
	if legacy {
		path = serviceAccountTokenFile
	}
	if credential := vh.vault.Credential; credential != nil {
		if credential.ServiceAccountName != "" {
			token, err := GenerateBoundServiceAccountToken(ctx, credential.ServiceAccountName, vh.namespace, vh.acs)
			return []byte(token), err
		}
		path = credential.ServiceAccount
	}

	var allowed []string
	if !legacy {
		allowed = globalConfig.serviceAccountTokenAllowedAudiences()
		if len(allowed) == 0 {
			return nil, fmt.Errorf("no approved service account token audiences; configure %s", ServiceAccountTokenAudiencesEnvVar)
		}
	}
	if path == "" {
		return nil, errors.New("k8s SA file not in config or serviceAccountName not supplied")
	}
	token, err := readKubernetesServiceAccountProjectedToken(path)
	if err != nil {
		return nil, err
	}
	if legacy {
		return token, nil
	}
	if err := validateK8sSATokenAudiences(token, allowed); err != nil {
		return nil, err
	}
	return token, nil
}

// validateAddress checks the Vault destination before accessing credentials.
func (vh *HashicorpVaultHandler) validateAddress(logger logr.Logger) error {
	policy := globalConfig.OutboundEndpointPolicy
	switch policy {
	case "", outboundPolicyOff:
		return nil
	case outboundPolicyWarn, outboundPolicyEnforce:
	default:
		return fmt.Errorf("unsupported %s.hashiCorpVault.mode %q", OutboundFilterEnvVar, policy)
	}
	allowed := globalConfig.AllowedOutboundEndpoints
	for _, endpoint := range allowed {
		if vaultAddressesEqual(endpoint, vh.vault.Address) {
			return nil
		}
	}
	if policy == outboundPolicyWarn {
		logger.Info("Warning: Vault endpoint is outside the allowlist; credentials may be sent to an untrusted destination. Configure KEDA_OUTBOUND_FILTER.hashiCorpVault with mode enforce and trusted allowedEndpoints", "vaultOrigin", vh.origin())
		return nil
	}
	if len(allowed) == 0 {
		return errors.New("no outbound endpoint allowlist is configured in enforce mode (KEDA_OUTBOUND_FILTER.hashiCorpVault.allowedEndpoints)")
	}
	return fmt.Errorf("vault endpoint %q is not in the configured allowlist (KEDA_OUTBOUND_FILTER.hashiCorpVault.allowedEndpoints)", vh.origin())
}

func (vh *HashicorpVaultHandler) origin() string {
	address, err := url.Parse(vh.vault.Address)
	if err != nil {
		return "<invalid endpoint>"
	}
	return (&url.URL{Scheme: address.Scheme, Host: address.Host}).String()
}

// vaultAddressesEqual compares two Vault addresses by scheme+host+port, ignoring path and trailing
// slashes, to avoid trivial allowlist bypasses via string prefixing.
func vaultAddressesEqual(a, b string) bool {
	ua, erra := url.Parse(strings.TrimSpace(a))
	ub, errb := url.Parse(strings.TrimSpace(b))
	if erra != nil || errb != nil {
		return false
	}
	if ua.User != nil || ub.User != nil || ua.Hostname() == "" || ub.Hostname() == "" {
		return false
	}
	if ua.Scheme != "http" && ua.Scheme != "https" || ub.Scheme != "http" && ub.Scheme != "https" {
		return false
	}
	return strings.EqualFold(ua.Scheme, ub.Scheme) && strings.EqualFold(ua.Host, ub.Host)
}

// renewToken takes charge of renewing the vault token
