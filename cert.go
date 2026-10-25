package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
	"os"
	"time"

	"github.com/sirupsen/logrus"
)

func (p *MITMProxy) generateCA() error {
	caCertPath := p.caCertPath
	if caCertPath == "" {
		caCertPath = "mitm-ca-cert.pem"
	}
	caKeyPath := p.caKeyPath
	if caKeyPath == "" {
		caKeyPath = "mitm-ca-key.pem"
	}

	certData, certErr := os.ReadFile(caCertPath)
	keyData, keyErr := os.ReadFile(caKeyPath)
	if certErr == nil || keyErr == nil {
		if certErr != nil {
			return fmt.Errorf("读取CA证书失败（私钥存在但证书不可用）: %w", certErr)
		}
		if keyErr != nil {
			return fmt.Errorf("读取CA私钥失败（证书存在但私钥不可用）: %w", keyErr)
		}
		if err := p.loadCA(certData, keyData); err != nil {
			return fmt.Errorf("加载现有CA失败: %w", err)
		}
		logrus.Infof("已加载现有CA证书: %s", caCertPath)
		return nil
	}
	if !os.IsNotExist(certErr) {
		return fmt.Errorf("读取CA证书失败: %w", certErr)
	}
	if !os.IsNotExist(keyErr) {
		return fmt.Errorf("读取CA私钥失败: %w", keyErr)
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

func (p *MITMProxy) loadCA(certPEM, keyPEM []byte) error {
	certBlock, _ := pem.Decode(certPEM)
	if certBlock == nil || certBlock.Type != "CERTIFICATE" {
		return fmt.Errorf("invalid CA certificate PEM")
	}
	certificate, err := x509.ParseCertificate(certBlock.Bytes)
	if err != nil {
		return fmt.Errorf("parse CA certificate: %w", err)
	}
	if !certificate.IsCA {
		return fmt.Errorf("certificate is not a CA")
	}
	if err := certificate.CheckSignatureFrom(certificate); err != nil {
		return fmt.Errorf("CA certificate is not self-signed: %w", err)
	}

	keyBlock, _ := pem.Decode(keyPEM)
	if keyBlock == nil || keyBlock.Type != "RSA PRIVATE KEY" {
		return fmt.Errorf("invalid CA private key PEM")
	}
	privateKey, err := x509.ParsePKCS1PrivateKey(keyBlock.Bytes)
	if err != nil {
		return fmt.Errorf("parse CA private key: %w", err)
	}
	publicKey, ok := certificate.PublicKey.(*rsa.PublicKey)
	if !ok || publicKey.E != privateKey.PublicKey.E || publicKey.N.Cmp(privateKey.PublicKey.N) != 0 {
		return fmt.Errorf("CA certificate and private key do not match")
	}

	p.caCert = certificate
	p.caKey = privateKey
	p.caCertPEM = append([]byte(nil), certPEM...)
	p.caKeyPEM = append([]byte(nil), keyPEM...)
	return nil
}

func (p *MITMProxy) getCertForHost(host string) (*tls.Certificate, error) {
	// 从缓存获取
	if cert := p.certCache.Get(host); cert != nil {
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

	// 缓存证书
	p.certCache.Set(host, cert)

	return cert, nil
}
