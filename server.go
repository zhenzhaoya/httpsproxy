package httpsproxy

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"log"
	"math/big"
	"net/http"
	"os"
	"time"

	"github.com/zhenzhaoya/httpsproxy/config"
)

type H map[string]string
type CookieCache struct {
	Proxy  string
	Cookie []string
}

type UserCache struct {
	Cookie    []string
	UserAgent string
	Proxy     string
	Sid       string
	Count     int
}

type ProxyEx struct {
	userCache     map[string][]*UserCache //[domain][]{Cookie,UserAgent,IP}
	config        *config.Config
	useProxy      bool
	collectCookie bool

	BeforeRequest func(http.ResponseWriter, *http.Request) bool
	AfterResponse func(*http.Response, *http.Request)
}

func json2userCache(b []byte) (map[string][]*UserCache, error) {
	c := make(map[string][]*UserCache)
	err := json.Unmarshal(b, &c)
	return c, err
}

var (
// myConfig         *config.Config
// proxyCache       map[string]*CookieCache = make(map[string]*CookieCache)
// cookieCache      map[string]H            = make(map[string]H)
// domainProxyCache H                       = make(H)
)

var logger = log.New(os.Stderr, "httpsproxy:", log.Llongfile|log.LstdFlags)

func GetAPP() *ProxyEx {
	app := &ProxyEx{userCache: make(map[string][]*UserCache), collectCookie: true}
	return app
}

func (self *ProxyEx) Start(config *config.Config) {
	self.config = config
	cert, err := genCertificate()
	if err != nil {
		logger.Fatal(err)
	}

	server := &http.Server{
		Addr:      config.Addr,
		TLSConfig: &tls.Config{Certificates: []tls.Certificate{cert}},
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			self.proxyHandler(w, r)
		}),
	}

	logger.Fatal(server.ListenAndServe())
}

func genCertificate() (cert tls.Certificate, err error) {
	rawCert, rawKey, err := generateKeyPair()
	if err != nil {
		return
	}
	return tls.X509KeyPair(rawCert, rawKey)
}

func generateKeyPair() (rawCert, rawKey []byte, err error) {
	// Create private key and self-signed certificate
	// Adapted from https://golang.org/src/crypto/tls/generate_cert.go

	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return
	}
	validFor := time.Hour * 24 * 365 * 10 // ten years
	notBefore := time.Now()
	notAfter := notBefore.Add(validFor)
	serialNumberLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serialNumber, err := rand.Int(rand.Reader, serialNumberLimit)
	template := x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			Organization: []string{"Zarten"},
		},
		NotBefore: notBefore,
		NotAfter:  notAfter,

		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}
	derBytes, err := x509.CreateCertificate(rand.Reader, &template, &template, &priv.PublicKey, priv)
	if err != nil {
		return
	}

	rawCert = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: derBytes})
	rawKey = pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(priv)})

	return
}
