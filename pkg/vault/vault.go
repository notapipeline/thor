package vault

import (
	"encoding/base64"
	"fmt"
	"regexp"
	"strings"
	"time"

	vault "github.com/hashicorp/vault/api"
	"github.com/notapipeline/thor/pkg/config"
	"github.com/notapipeline/thor/pkg/loki"
	log "github.com/sirupsen/logrus"
)

const (
	TTL     = "5m"
	MAX_TTL = "5m"
	STANDBY = "standby"
)

type Result struct {
	Path string
}

type Vault struct {
	config        *config.VaultConfig
	encryptionkey string
}

func NewVault(c *config.VaultConfig) *Vault {
	v := Vault{
		config: c,
	}
	return &v
}

func (v *Vault) Init() error {
	var (
		key string
		err error
	)

	if key, err = v.GetEncryptionKey(); err != nil || key == "" {
		if key, err = v.CreateEncryptionKey(v.config.TokenPolicy); err != nil {
			return err
		}
		if err = v.StoreEncryptionKey(key); err != nil {
			return err
		}
	}
	return nil
}

func (v *Vault) CreateEncryptionKey(policy *config.Policy) (string, error) {
	client, err := v.roleClient()
	s, err := client.Logical().Write("gen/password", map[string]interface{}{})
	if err != nil {
		return "", err
	}

	var (
		key string
		ok  bool
	)
	if key, ok = s.Data["value"].(string); !ok {
		return "", fmt.Errorf("Failed to generate new encryption key")
	}
	reg := regexp.MustCompile(fmt.Sprintf("[%s]", policy.ExcludeCharacters))
	key = reg.ReplaceAllString(key, "")
	return key[:policy.Length], nil
}

func (v *Vault) StoreEncryptionKey(key string) error {
	return v.writeInternal("apikey", key, v.config.EncryptionKey)
}

func (v *Vault) GetEncryptionKey() (string, error) {
	if v.encryptionkey == "" {
		client, err := v.roleClient()
		if err != nil {
			return "", err
		}
		response, err := client.Logical().Read(v.config.EncryptionKey)
		if response == nil || err != nil {
			return "", err
		}

		if _, ok := response.Data["apikey"].(string); !ok {
			return "", fmt.Errorf("No such entry created")
		}
		v.encryptionkey = response.Data["apikey"].(string)
	}
	return v.encryptionkey, nil
}

// Unwrap a response wrapped token - used in the agent
func (v *Vault) Unwrap(token, namespace string) (string, error) {
	client, err := vault.NewClient(v.config.VaultConfig)
	if err != nil {
		return "", fmt.Errorf("unable to initialize Vault client: %w", err)
	}
	if namespace != "" {
		client.SetNamespace(namespace)
	}

	data := make(map[string]interface{})
	data["token"] = token
	response, err := client.Logical().Unwrap(token)
	if err != nil {
		return "", err
	}
	return response.Data["value"].(string), nil
}

// response wrap a given piece of information and return
// the secret assigned to that wrap.
func (v *Vault) Wrap(what interface{}) (string, error) {
	data := make(map[string]interface{})
	data["value"] = what

	client, err := v.roleClient()
	if err != nil {
		return "", err
	}
	client.SetWrappingLookupFunc(func(string, string) string { return TTL })
	response, err := client.Logical().Write("/sys/wrapping/wrap", data)
	if err != nil {
		return "", err
	}
	info := response.WrapInfo
	return info.Token, nil
}

// Store an orphaned child token based on the token used to request rotation
//
// This token will have a specific read only policy created against it but the ability
// to create child tokens.
func (v *Vault) CreateAndStoreChildCreationToken(token, namespace string, policyPaths []string) error {
	client, err := v.tokenClient(token, namespace)

	var (
		policy    string = "path \"auth/token/create\" {\n  capabilities = [\"create\", \"update\"]\n}\n\n"
		renewable bool   = false
	)
	for _, path := range policyPaths {
		policy += fmt.Sprintf("path \"%s\" {\n  capabilities = [\"list\", \"read\"]\n}\n\n", path)
	}

	// store new policy into namespace
	t := time.Now()
	policyName := fmt.Sprintf("rotation-policy-%s", t.Format("2006-01-02-15-04"))
	if err := client.Sys().PutPolicy(policyName, policy); err != nil {
		return err
	}

	// Create a new child token, orphaned, with the new policy attached to it
	childTokenLease, err := client.Auth().Token().Create(&vault.TokenCreateRequest{
		DisplayName:    fmt.Sprintf("Auto-Rotation-Parent-%s", policyName),
		Policies:       []string{policyName},
		NoParent:       true,
		TTL:            TTL,
		ExplicitMaxTTL: MAX_TTL,
		Renewable:      &renewable,
		NumUses:        0,
	})

	if err != nil {
		return fmt.Errorf("Failed to create a limited child token for namespace %s: %s", namespace, err)
	}

	key, err := v.GetEncryptionKey()
	if err != nil {
		return err
	}

	var encrypted string = v.Encrypt(childTokenLease.Auth.ClientToken, key)
	return v.writeInternal(namespace, encrypted, v.config.SecureTokenPath)
}

// Writes to a KV version 1 store using the backend login
// for the Thor server.
//
// Any changes to paths tracked under this should not have
// their history tracked and should be considered ephemeral
func (v *Vault) writeInternal(key, value, path string) error {
	client, err := v.roleClient()
	if err != nil {
		return err
	}
	response, err := client.Logical().Read(path)
	if err != nil {
		return err
	}

	var data = make(map[string]interface{})
	if response != nil {
		data = response.Data
	}
	data[key] = value

	_, err = client.Logical().Write(path, data)
	if err != nil {
		return err
	}
	return nil
}

// Get a response wrapped token for client usage
func (v *Vault) GetToken(namespace, encryptionKey string) (string, error) {
	client, err := v.roleClient()
	if err != nil {
		return "", err
	}
	// SecureTokenPath **must** be a path to a KV version 1 store
	// We should NEVER track the history of tokens under this path
	response, err := client.Logical().Read(v.config.SecureTokenPath)
	if response == nil {
		return "", fmt.Errorf("No keys have been stored for accessing the requested namespace %s", namespace)
	} else if err != nil {
		return "", err
	}

	var (
		namespaceToken string
		ok             bool
		renewable      bool = false
	)
	if namespaceToken, ok = response.Data[namespace].(string); !ok {
		return "", fmt.Errorf("No keys have been stored for accessing the requested namespace %s", namespace)
	}

	key, err := v.GetEncryptionKey()
	if err != nil {
		return "", err
	}
	namespaceToken = v.Decrypt(namespaceToken, key)

	// TODO
	// Check if this token has expired before logging in with it.
	// If it's expired, we return a STANDBY response to the agent
	// to inform it that there is no change currently expected
	s, err := client.Auth().Token().Lookup(namespaceToken)
	if err != nil || s == nil {
		return STANDBY, err
	}

	// If the namespace token has not expired, create a child token
	// from it to send back to the agent
	client, err = v.tokenClient(namespaceToken, namespace)
	if err != nil {
		return "", err
	}

	// now create a child token
	childTokenLease, err := client.Auth().Token().Create(&vault.TokenCreateRequest{
		DisplayName:    fmt.Sprintf("Auto-Rotation"),
		TTL:            TTL,
		ExplicitMaxTTL: MAX_TTL,
		Renewable:      &renewable,
	})
	if err != nil {
		return "", fmt.Errorf("Failed to create a limited child token for namespace %s: %s", namespace, err)
	}

	var encrypted string = v.Encrypt(childTokenLease.Auth.ClientToken, encryptionKey)

	data := make(map[string]interface{})
	data["value"] = encrypted

	client.SetWrappingLookupFunc(func(string, string) string { return TTL })
	response, err = client.Logical().Write("/sys/wrapping/wrap", data)
	if err != nil {
		return "", err
	}

	info := response.WrapInfo
	return fmt.Sprintf("tok|%s", info.Token), nil
}

// encrypt a string and return the result
func (v *Vault) Encrypt(what, key string) string {
	encrypted, _ := encrypt([]byte(what), key)
	return base64.StdEncoding.EncodeToString(encrypted)
}

// Decrypt an encrypted string and return the plaintext
func (v *Vault) Decrypt(what, key string) string {
	passphrase, _ := base64.StdEncoding.DecodeString(what)
	decrypted, _ := decrypt(passphrase, key)
	return string(decrypted)
}

/// Searches a vault namespace for a given password
func (v *Vault) Search(password, token, namespace string, results *[]Result) error {
	var err error
	log.Debug("Creating primary client")
	client, err := v.tokenClient(token, namespace)
	if err != nil {
		return err
	}

	// first get a list of all KV paths

	log.Debug("Getting mount points")
	mounts, err := client.Logical().Read("/sys/mounts")
	if err != nil {
		return err
	}

	log.Debugf("Found %d mounts", len(mounts.Data))
	kv := make([]string, 0)
	for k, data := range mounts.Data {
		details := data.(map[string]interface{})
		if details["type"].(string) == "kv" {
			options := details["options"].(map[string]interface{})
			if options["version"].(string) == "2" {
				k = strings.ReplaceAll(fmt.Sprintf("%s/metadata/", k), "//", "/")
			}
			kv = append(kv, k)
		}
	}

	kvchan := make(chan []string)
	for _, path := range kv {
		go func(password, token, namespace, path string) {
			results, _ := v.getKVSecrets(password, token, namespace, path)
			kvchan <- results
		}(password, token, namespace, path)
	}

	secrets := make([]string, 0)
	for range kv {
		k := <-kvchan
		secrets = append(secrets, k...)
	}

	for _, p := range secrets {
		*results = append(*results, Result{
			Path: p,
		})
	}
	return nil
}

func (v *Vault) ClearRotation(token, namespace, path string) {
	client, err := v.tokenClient(token, namespace)
	if err != nil {
		log.Error(err)
		return
	}

	var v2 bool = false
	// Get data at path
	secret, err := client.Logical().Read(path)
	if err != nil || secret == nil {
		return
	}
	log.Errorf("%+v", err)

	data := make(map[string]interface{})
	if _, ok := secret.Data["data"].(map[string]interface{}); ok {
		data = secret.Data["data"].(map[string]interface{})
		v2 = true
	} else {
		data = secret.Data
	}

	d := make(map[string]interface{})
	data["rotated"] = ""
	if v2 {
		d["data"] = data
	} else {
		d = data
	}

	_, err = client.Logical().Write(path, d)
	if err != nil {
		log.Error(err)
	}
}

// Rotates the contents of a path matching `search`
//
// `search` can be either a key at a given path, or the secret value at a given path
//
// If a match is found, the value stored at that key will be updated
func (v *Vault) Rotate(path, token, search, namespace string, compromised bool, logChannel *chan loki.SimpleMessage) []error {
	var (
		errors []error = make([]error, 0)
		err    error
		ok     bool
		v2     bool = false
	)
	search = strings.ToLower(search)
	client, err := v.tokenClient(token, namespace)
	if err != nil {
		log.Error(err)
		return errors
	}

	// Get data at path
	secret, err := client.Logical().Read(path)
	if err != nil {
		errors = append(errors, err)
		return errors
	}

	if secret == nil {
		return errors
	}

	data := make(map[string]interface{})
	if _, ok := secret.Data["data"].(map[string]interface{}); ok {
		data = secret.Data["data"].(map[string]interface{})
		v2 = true
	} else {
		data = secret.Data
	}

	var rotated []string = make([]string, 0)
	if val, ok := data["rotated"]; ok {
		r := strings.Split(val.(string), ",")
		for _, s := range r {
			if s != "" {
				rotated = append(rotated, s)
			}
		}
	}

	var changed bool = false
	for key, value := range data {
		// Never update the rotated key at a given path
		if key == "rotated" {
			continue
		}

		var (
			keysearch   bool = strings.ToLower(key) == search && !compromised
			valuesearch bool = strings.ToLower(value.(string)) == search && compromised
		)

		if keysearch || valuesearch {
			var update bool = true

			// Generate a new secret
			*logChannel <- loki.SimpleMessage{
				Time:    time.Now().Format("2006-01-02 15:04:05"),
				Host:    "thor",
				Message: fmt.Sprintf("Generating new password for %s/%s", namespace, path),
			}

			s, err := client.Logical().Write("gen/password", map[string]interface{}{})
			if err != nil {
				errors = append(errors, fmt.Errorf("Unable to generate password: %w", err))
				update = false
			}

			var newPass string
			if newPass, ok = s.Data["value"].(string); !ok {
				errors = append(errors, fmt.Errorf("Data type assertion failed: %T %#v", s.Data["data"], s.Data["data"]))
				update = false
			}

			if update {
				rotated = append(rotated, key)
				value = newPass
				changed = true
				if v.config.PasswordPolicy != nil {
					reg := regexp.MustCompile(fmt.Sprintf("[%s]", v.config.PasswordPolicy.ExcludeCharacters))
					newPass = reg.ReplaceAllString(newPass, "")
					value = newPass[:v.config.PasswordPolicy.Length]
				}
			}
		}
		data[key] = value
	}

	// we store a list of keys that have been rotated back into vault
	// to allow server credential management scripts to understand
	// any and all accounts to update keys for.
	data["rotated"] = strings.Join(rotated, ",")
	d := make(map[string]interface{})
	if v2 {
		d["data"] = data
	} else {
		d = data
	}

	if changed {
		// Generate a new secret
		*logChannel <- loki.SimpleMessage{
			Time:    time.Now().Format("2006-01-02 15:04:05"),
			Host:    "thor",
			Message: fmt.Sprintf("Storing updated credentials for %s/%s", namespace, path),
		}

		_, err = client.Logical().Write(path, d)
		if err != nil {
			errors = append(errors, fmt.Errorf("Unable to write secret: %w", err))
		}
	}

	return errors
}

type child struct {
	Path   string
	Secret vault.Secret
}

// finds a list of paths containing password from kv store
func (v *Vault) getKVSecrets(password, token, namespace, path string) ([]string, error) {
	secrets := make([]string, 0)
	if string(path[0]) != "/" {
		path = "/" + path
	}
	log.Debugf("Checking %s", path)

	client, _ := v.tokenClient(token, namespace)
	// Get a list of all items in Vault at a given paths
	contents, err := client.Logical().List(path)
	if err != nil {
		return nil, err
	}

	// If we have an empty store, skip over it
	if contents == nil {
		return secrets, nil
	}

	secretPaths := make([]string, 0)
	folders := make([]string, 0)
	for _, k := range contents.Data["keys"].([]interface{}) {
		key := strings.ReplaceAll(fmt.Sprintf("%s%s", path, k.(string)), "//", "/")
		if key[len(key)-1:] == "/" {
			folders = append(folders, key)
		} else {
			// If this is a KV version 2 path, we read secrets from data, not metadata
			ps := strings.Split(key, "/")
			if ps[2] == "metadata" {
				ps[2] = "data"
				key = strings.Join(ps, "/")
			}
			secretPaths = append(secretPaths, key)
		}
	}

	// Branch out for folders
	if len(folders) != 0 {
		childrensChannel := make(chan []string, 1)
		for _, p := range folders {
			go func(password, token, namespace, path string) {
				results, _ := v.getKVSecrets(password, token, namespace, path)
				childrensChannel <- results
			}(password, token, namespace, p)
		}

		for range folders {
			children := <-childrensChannel
			secrets = append(secrets, children...)
		}
	}

	// Now parse secrets
	childrensChannel := make(chan *child)
	for _, p := range secretPaths {
		go func(p, t, n string) {
			client, _ := v.tokenClient(t, n)
			c := child{
				Path: p,
			}
			secret, err := client.Logical().Read(p)
			if err == nil {
				c.Secret = *secret
			}
			childrensChannel <- &c
		}(p, token, namespace)
	}

	// Secrets may come back out of order so just iterate the length
	for range secretPaths {
		secret := <-childrensChannel
		data := make(map[string]interface{})

		if _, ok := secret.Secret.Data["data"].(map[string]interface{}); ok {
			data = secret.Secret.Data["data"].(map[string]interface{})
		} else {
			data = secret.Secret.Data
		}

		for _, value := range data {
			if value.(string) == password {
				secrets = append(secrets, secret.Path)
			}
		}
	}
	return secrets, nil
}

// Gets a list of credentials that need to be rotated on a machine
func (v *Vault) Read(path, token, namespace string) (map[string]string, error) {
	credentials := make(map[string]string)
	client, err := v.tokenClient(token, namespace)
	if err != nil {
		return credentials, err
	}
	secret, err := client.Logical().Read(path)
	if err != nil {
		return credentials, err
	}

	data := make(map[string]interface{})
	if _, ok := secret.Data["data"].(map[string]interface{}); ok {
		data = secret.Data["data"].(map[string]interface{})
	} else {
		data = secret.Data
	}

	var (
		rotated      string
		ok           bool
		rotationList []string
	)
	if rotated, ok = data["rotated"].(string); ok {
		rotationList = strings.Split(rotated, ",")
	}
	for _, key := range rotationList {
		var value string
		if value, ok = data[key].(string); ok {
			credentials[key] = value
		}
	}
	return credentials, nil
}
