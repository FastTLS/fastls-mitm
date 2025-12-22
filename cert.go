package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net"
	"os"
	"time"

	"github.com/sirupsen/logrus"
)

func (p *MITMProxy) generateCA() error {
	caCertPath := "mitm-ca-cert.pem"
	caKeyPath := "mitm-ca-key.pem"

	if certData, err := os.ReadFile(caCertPath); err == nil {
		if keyData, err := os.ReadFile(caKeyPath); err == nil {
			block, _ := pem.Decode(certData)
			if block != nil {
				p.caCert, _ = x509.ParseCertificate(block.Bytes)
			}
			keyBlock, _ := pem.Decode(keyData)
			if keyBlock != nil {
				p.caKey, _ = x509.ParsePKCS1PrivateKey(keyBlock.Bytes)
			}
			p.caCertPEM = certData
			p.caKeyPEM = keyData
			logrus.Infof("已加载现有CA证书: %s", caCertPath)
			return nil
		}
	}

	logrus.Info("正在生成新的CA根证书（有效期15年）...")

	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return err
	}

	now := time.Now()
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			Organization:  []string{"Fastls MITM Proxy"},
			Country:       []string{"CN"},
			Province:      []string{""},
			Locality:      []string{""},
			StreetAddress: []string{""},
			PostalCode:    []string{""},
		},
		NotBefore:             now,
		NotAfter:              now.AddDate(15, 0, 0),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
		BasicConstraintsValid: true,
		IsCA:                  true,
		MaxPathLen:            0,
	}

	certDER, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		return err
	}

	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)})

	if err := os.WriteFile(caCertPath, certPEM, 0644); err != nil {
		return err
	}
	if err := os.WriteFile(caKeyPath, keyPEM, 0600); err != nil {
		return err
	}

	p.caCert, _ = x509.ParseCertificate(certDER)
	p.caKey = key
	p.caCertPEM = certPEM
	p.caKeyPEM = keyPEM

	logrus.Infof("CA证书已生成并保存: %s", caCertPath)
	logrus.Infof("CA证书有效期: %s 至 %s", template.NotBefore.Format("2006-01-02"), template.NotAfter.Format("2006-01-02"))
	logrus.Infof("请将 %s 添加到系统信任的根证书颁发机构", caCertPath)

	return nil
}

func (p *MITMProxy) getCertForHost(host string) (*tls.Certificate, error) {
	p.certMutex.RLock()
	if cert, ok := p.certCache[host]; ok {
		p.certMutex.RUnlock()
		return cert, nil
	}
	p.certMutex.RUnlock()

	p.certMutex.Lock()
	defer p.certMutex.Unlock()

	if cert, ok := p.certCache[host]; ok {
		return cert, nil
	}

	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, err
	}

	now := time.Now()
	template := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().Unix()),
		Subject: pkix.Name{
			CommonName:   host,
			Organization: []string{"Fastls MITM Proxy"},
		},
		NotBefore:   now,
		NotAfter:    now.AddDate(1, 0, 0),
		KeyUsage:    x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames:    []string{host, "*." + host},
		IPAddresses: []net.IP{net.ParseIP("127.0.0.1"), net.ParseIP("::1")},
	}

	certDER, err := x509.CreateCertificate(rand.Reader, template, p.caCert, &key.PublicKey, p.caKey)
	if err != nil {
		return nil, err
	}

	cert := &tls.Certificate{
		Certificate: [][]byte{certDER},
		PrivateKey:  key,
	}

	p.certCache[host] = cert

	return cert, nil
}
