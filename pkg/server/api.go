package server

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"strconv"
	"time"

	"github.com/boltdb/bolt"
	"github.com/gin-gonic/gin"
	"github.com/pion/dtls/v2"
	"github.com/notapipeline/thor/pkg/vault"

	log "github.com/sirupsen/logrus"
)

const (
	MAX_AUTH_FAILURES  = 1
	MAX_USES           = 1
	EXPIRY_TABLE       = "expiry"
	FAILURES_TABLE     = "failures"
	DEVICES_TABLE      = "devices"
	CERTIFICATES_TABLE = "certificates"
	EX_EMPLOYEES_TABLE = "ex-employees"
	SHASUM             = "shasum"
	AGENT_PORT         = 7468
)

func (server *Server) createBuckets() {
	tables := []string{
		EXPIRY_TABLE,
		FAILURES_TABLE,
		DEVICES_TABLE,
		CERTIFICATES_TABLE,
		EX_EMPLOYEES_TABLE,
		SHASUM,
	}

	errors := make([]error, 0)
	if err := server.bolt.Update(func(tx *bolt.Tx) error {
		for _, table := range tables {
			_, err := tx.CreateBucketIfNotExists([]byte(table))
			if err != nil {
				errors = append(errors, err)
			}
		}
		if len(errors) > 0 {
			return fmt.Errorf("errors were raised")
		}
		return nil
	}); err != nil && len(errors) > 0 {
		for _, err := range errors {
			log.Error(err)
		}
	}
}

func (server *Server) Decrypt(c *gin.Context) {
	request := make(map[string]interface{})
	if err := c.ShouldBind(&request); err != nil {
		server.reject(c, fmt.Sprintf("Request bind failure %v", err))
		return
	}

	message := server.vault.Decrypt(request["token"].(string), request["key"].(string))
	server.accept(c, message)
}

func (server *Server) WhatsMyIP(c *gin.Context) {
	var clientIP string = c.ClientIP()
	if err := server.bolt.View(func(tx *bolt.Tx) error {
		devices := tx.Bucket([]byte(DEVICES_TABLE))
		if devices == nil {
			log.Errorf("Failed to read database")
			return fmt.Errorf("Internal server error. Please contact the system administrator")
		}

		var value []byte
		if value = devices.Get([]byte(clientIP)); value == nil {
			return fmt.Errorf("No such device is known to the system: %s", clientIP)
		}
		return nil
	}); err != nil {
		server.reject(c, "go away")
		return
	}
	server.accept(c, clientIP)
}

// TODO
// This method has no authentication system on it.
// Before we can use it in a production environment,
// we must authenticate the endpoint and devices connecting
// to it to prevent it being abused by external actors
func (server *Server) AddDevices(c *gin.Context) {
	request := make(map[string]interface{})
	if err := c.ShouldBind(&request); err != nil {
		server.reject(c, fmt.Sprintf("Request bind failure %v", err))
		return
	}

	var trusted bool = false
	for _, address := range server.config.TrustedInbound {
		if c.ClientIP() == address {
			trusted = true
		}
	}

	if !trusted {
		server.reject(c, "go away")
		return
	}

	deviceList, ok := request["devices"].([]interface{})
	if !ok {
		server.reject(c, fmt.Sprintf("Invalid devices - should be list got %T %+v", request["devices"], request["devices"]))
		return
	}

	if err := server.bolt.Update(func(tx *bolt.Tx) error {
		devices := tx.Bucket([]byte(DEVICES_TABLE))
		if devices == nil {
			log.Errorf("Failed to open database for write:")
			return fmt.Errorf("Internal server error. Please contact the system administrator")
		}

		for _, device := range deviceList {
			err := devices.Put([]byte(device.(string)), []byte(""))
			if err != nil {
				log.Errorf("Failed to write to devices table:", err)
				return fmt.Errorf("Failed to add device. Please try again.")
			}
		}
		return nil
	}); err != nil {
		server.reject(c, err.Error())
		return
	}
	server.accept(c, "done")
}

type shaSum struct {
	Sha  string `json:"sha"`
	Name string `json:"name"`
}

type ShaSums struct {
	Shasums []shaSum `json:"shas"`
}

// TODO
// This is something of a duplication of the method above.
// Would be worth abstracting the common functionality to
// make the code a little more readable
func (server *Server) AddShaSum(c *gin.Context) {
	request := ShaSums{}
	if err := c.ShouldBind(&request); err != nil {
		server.reject(c, fmt.Sprintf("Request bind failure %v", err))
		return
	}

	var trusted bool = false
	for _, address := range server.config.TrustedInbound {
		if c.ClientIP() == address {
			trusted = true
		}
	}

	if !trusted {
		server.reject(c, "go away")
		return
	}

	if err := server.bolt.Update(func(tx *bolt.Tx) error {
		shasum := tx.Bucket([]byte(SHASUM))
		if shasum == nil {
			log.Errorf("Failed to open database for write:")
			return fmt.Errorf("Internal server error. Please contact the system administrator")
		}

		// TODO:
		// How do we prove that each accepted SHASUM is a valid 256sum
		// for what we're being asked to store and validate?
		//
		// one way to do this would be to give Thor an address of where
		// it can download the binary and verify the sha against that version
		//
		// This might seem like an unnecessary overhead but when we're
		// dealing with the security of devices deep inside the network,
		// more is better...
		//
		// Another way might be to simply have a trusted signing key
		// loaded in through vault by an admin member and verify the
		// shasum with the signing key?
		for _, sum := range request.Shasums {
			err := shasum.Put([]byte(sum.Sha), []byte(sum.Name))
			if err != nil {
				log.Errorf("Failed to write to shasum table:", err)
				return fmt.Errorf("Failed to add shasum. Please try again.")
			}
		}
		return nil
	}); err != nil {
		server.reject(c, err.Error())
		return
	}
	server.accept(c, "done")
}

type RegistrationRequest struct {
	Registration string `json:"registration_request"`
	Namespace    string `json:"namespace"`
	ShaSum       string `json:"shasum"`
}

func (server *Server) Register(c *gin.Context) {
	request := RegistrationRequest{}

	var (
		register string
		err      error
		clientIP string = c.ClientIP()
		key      string
	)

	if err = c.ShouldBind(&request); err != nil {
		server.reject(c, fmt.Sprintf("Request bind failure %v", err))
		return
	}

	if request.Registration == "" {
		server.reject(c, "Invalid registration request")
		return
	}

	if request.Namespace == "" {
		server.reject(c, "Invalid namespace requested")
		return
	}

	if request.ShaSum == "" {
		server.reject(c, "Invalid shasum detected")
	}

	log.Infof("Recieved ShaSum %s for client %s", request.ShaSum, clientIP)

	var (
		certificate string = ""
		shasum      string = ""
	)
	if err := server.bolt.View(func(tx *bolt.Tx) error {
		devices := tx.Bucket([]byte(DEVICES_TABLE))
		if devices == nil {
			log.Errorf("Failed to read devices database")
			return fmt.Errorf("Internal server error. Please contact the system administrator")
		}

		certificates := tx.Bucket([]byte(CERTIFICATES_TABLE))
		if certificates == nil {
			log.Errorf("Failed to read certificates database")
			return fmt.Errorf("Internal server error. Please contact the system administrator")
		}

		shasums := tx.Bucket([]byte(SHASUM))
		if shasums == nil {
			log.Errorf("Failed to read shasum database")
			return fmt.Errorf("Internal server error. Please contact the system administrator")
		}

		var value []byte
		if value = devices.Get([]byte(clientIP)); value == nil {
			return fmt.Errorf("No such device is known to the system: %s", clientIP)
		}

		if value = certificates.Get([]byte(clientIP)); value != nil {
			certificate = string(value)
		}

		if value = shasums.Get([]byte(request.ShaSum)); value != nil {
			shasum = string(value)
		}

		return nil
	}); err != nil {
		server.reject(c, err.Error())
		return
	}

	if certificate != "" && certificate != request.Registration {
		server.reject(c, "Invalid certificate provided for client IP")
		return
	}

	if shasum == "" {
		server.reject(c, fmt.Sprintf("Invalid shasum for agent %s", clientIP))
		return
	}

	if key == "" {
		key, err = server.vault.CreateEncryptionKey(server.config.Vault.TokenPolicy)
		if err != nil {
			server.reject(c, "Unable to create encryption key")
			return
		}
	}

	if err := server.bolt.Update(func(tx *bolt.Tx) error {
		devices := tx.Bucket([]byte(DEVICES_TABLE))
		if devices == nil {
			log.Errorf("Failed to open database for write:", err)
			return fmt.Errorf("Internal server error. Please contact the system administrator")
		}

		err = devices.Put([]byte(clientIP), []byte(key))
		if err != nil {
			log.Errorf("Failed to write to devices table:", err)
			return fmt.Errorf("Failed to save API Key. Please try again.")
		}

		var n *bolt.Bucket
		n, err = tx.CreateBucketIfNotExists([]byte(request.Namespace))
		if err != nil {
			// non-fatal
			log.Errorf("Error creating butcket for device registration to %s", request.Namespace)
		}
		err = n.Put([]byte(clientIP), []byte(""))
		if err != nil {
			// non-fatal
			log.Errorf("Failed to store client IP in %s", request.Namespace)
		}

		if certificate == "" {
			certificates := tx.Bucket([]byte(CERTIFICATES_TABLE))
			if certificates == nil {
				log.Errorf("Failed to read certificates database")
				return fmt.Errorf("Internal server error. Please contact the system administrator")
			}

			if err = certificates.Put([]byte(clientIP), []byte(register)); err != nil {
				log.Errorf("Failed to store certificate for %s: %v", clientIP, err)
				return fmt.Errorf("Failed to save registration certificate. Please try again.")
			}
		}

		failures := tx.Bucket([]byte(FAILURES_TABLE))
		failures.Delete([]byte(clientIP))
		expiry := tx.Bucket([]byte(EXPIRY_TABLE))
		expiry.Delete([]byte(clientIP))

		return nil
	}); err != nil {
		server.reject(c, err.Error())
		return
	}

	server.accept(c, "Pending delivery")
	server.writetowrapped(clientIP, "", key, "key|")
}

type ApiResult struct {
	Status  string `json:"status"`
	Message string `json:"message"`
}

type TokenRequest struct {
	Token     string   `json:"token_request"`
	Namespace string   `json:"namespace"`
	Paths     []string `json:"paths"`
}

func (server *Server) Token(c *gin.Context) {
	request := TokenRequest{}
	var (
		err        error
		clientIP   string = c.ClientIP()
		reregister bool   = false
	)

	if err = c.ShouldBind(&request); err != nil {
		server.reject(c, "Request bind failure")
		return
	}

	if request.Token == "" {
		server.reject(c, "Invalid token request")
		return
	}

	if err := server.bolt.View(func(tx *bolt.Tx) error {
		devices := tx.Bucket([]byte(DEVICES_TABLE))
		if devices == nil {
			log.Errorf("Failed to read database:", err)
			return fmt.Errorf("Internal server error. Please contact the system administrator")
		}

		var value []byte
		if value = devices.Get([]byte(clientIP)); value == nil {
			return fmt.Errorf("No such device is known to the system")
		}

		if request.Token != string(value) {
			reregister = true
			return fmt.Errorf("Invalid client auth")
		}
		return nil
	}); err != nil {
		server.reject(c, err.Error())
		if reregister && server.checkReregistration(clientIP, FAILURES_TABLE) {
			server.writeto(clientIP, "reregister")
		}
		return
	}

	// check to see if the API key has expired in the system
	// this is forced every MAX_USES uses to better control security
	if server.checkReregistration(clientIP, EXPIRY_TABLE) {
		server.reject(c, "Client must re-register")
		server.writeto(clientIP, "reregister")
		return
	}

	var token string
	token, err = server.vault.GetToken(request.Namespace, request.Token)
	if err != nil && token != vault.STANDBY {
		log.Errorf("%v", err)
		server.reject(c, "Error creating token, please retry")
		return
	}

	server.accept(c, "Pending delivery")
	if len(token) != 0 {
		server.writeto(clientIP, token)
	}
}

// Check if a client must re-register
// Re-registration is forced if a client has too many authentication failures or a token has expired
func (server *Server) checkReregistration(clientIP, table string) bool {
	var (
		must  bool = false
		store int  = 0
		max        = MAX_AUTH_FAILURES
	)

	if table == EXPIRY_TABLE {
		max = MAX_USES
	}

	if err := server.bolt.View(func(tx *bolt.Tx) error {
		bucket := tx.Bucket([]byte(table))
		if bucket == nil {
			return fmt.Errorf("No such bucket for authentication %s", table)
		}

		var value []byte
		if value = bucket.Get([]byte(clientIP)); value != nil {
			store, _ = strconv.Atoi(string(value))
			store += 1
		}

		if store >= max {
			store = 0
			must = true
		}
		return nil
	}); err != nil {
		log.Error(err)
		return false
	}

	if err := server.bolt.Update(func(tx *bolt.Tx) error {
		bucket := tx.Bucket([]byte(table))
		if bucket == nil {
			return fmt.Errorf("No such bucket for authentication %s", table)
		}

		var err error
		if must {
			err = bucket.Delete([]byte(clientIP))
		} else {
			err = bucket.Put([]byte(clientIP), []byte(strconv.Itoa(store)))
		}
		if err != nil {
			return fmt.Errorf("Failed to write to %s table for device %s: %v", table, clientIP, err)
		}
		return nil
	}); err != nil {
		log.Error(err)
	}
	return must
}

func (server *Server) reject(c *gin.Context, reason string) {
	result := ApiResult{
		Status:  "rejected",
		Message: reason,
	}
	c.JSON(http.StatusForbidden, result)
}

func (server *Server) accept(c *gin.Context, reason string) {
	result := ApiResult{
		Status:  "accepted",
		Message: reason,
	}
	c.JSON(http.StatusAccepted, result)
}

// writeto sends a Response Wrapped UDP Datagram packet
func (server *Server) writetowrapped(address, forwardTo, message, prefix string) {
	contents := make(map[string]string)
	contents["message"] = message
	contents["forward"] = forwardTo

	data, err := server.vault.Wrap(message)
	if err != nil {
		log.Error(err)
	}
	server.writeto(address, fmt.Sprintf("%s%s", prefix, data))
}

// writeto sends a UDP Datagram packet
func (server *Server) writeto(address, message string) {
	log.Infof("Returning information over DTLS to %s:%d", address, AGENT_PORT)
	addr := &net.UDPAddr{IP: net.ParseIP(address), Port: AGENT_PORT}

	// TODO:
	// The agent presents a certificate on registration, we store this.
	// At the moment, there is no validation on that certificate but in the
	// majority of cases, we should be able to leverage that cert and make
	// this not require skip verification.
	//
	// If we require CA signing, we could probably make Thor carry this out
	// relatively easily...
	config := &dtls.Config{
		InsecureSkipVerify: true,
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	dtlsConn, err := dtls.DialWithContext(ctx, "udp", addr, config)
	if err != nil {
		log.Error(err)
		return
	}

	defer dtlsConn.Close()
	dtlsConn.Write([]byte(fmt.Sprintf("%s\n", message)))
}
