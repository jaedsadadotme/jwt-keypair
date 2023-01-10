package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"io/ioutil"
	"log"
	"os"
	"time"

	"github.com/golang-jwt/jwt"
)

func main() {
	// GenerateKey()
	Verify("eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJmb28iOiJiYXIiLCJuYmYiOjE0NDQ0Nzg0MDB9.NrhXDukrT9YfOeDLHvJSNXAYE6k0dOwIaoyn6tGjRUrfHYbr2EJJtqFf9-C3c8-LN7pS_DuKvBbfKWo-OjV2bLxfQBJDzoKOMxcZVqhaG_SBdgtAOXcIX6eTUeRaq8uGCzJuoEhzbVQhEqO-IkC_IoCRzb0f1hrDUc3sA3btItRLu6UW6xMwMW0O3Lkp_3yufl5htOjjJOh-8aWKdaWjU3t0KSItgKlZ6BSZsH4SJ0EH2RiRgWMZUpSMuJ2VqEl76M7zHnndZvJfiffw42IUm2NxafpBCYmfTCsbyZCHuvybotwhhiHopdX_bnw2h1EL115A0ZIFbPZmd_T5I4L-iw")
}

func Sign() {
	private, err := ioutil.ReadFile("private.key")
	if err != nil {
		log.Println(err.Error())
	}
	// log.Println("SecretKey => ", private)
	privateKey, err := jwt.ParseRSAPrivateKeyFromPEM(private)
	if err != nil {
		log.Println("parse key error")
	}

	token := jwt.NewWithClaims(jwt.SigningMethodRS256, jwt.MapClaims{
		"foo": "bar",
		"nbf": time.Date(2015, 10, 10, 12, 0, 0, 0, time.UTC).Unix(),
	})

	// Sign and get the complete encoded token as a string using the secret
	tokenString, err := token.SignedString(privateKey)
	if err != nil {
		log.Println(err.Error())
	}
	fmt.Println(tokenString)
}
func Verify(token string) {
	public, err := ioutil.ReadFile("public.pem")
	if err != nil {
		log.Println(err.Error())
	}
	publicKey, err := jwt.ParseRSAPublicKeyFromPEM(public)
	if err != nil {
		log.Println(err)
	}
	claims := jwt.MapClaims{}
	_, err = jwt.ParseWithClaims(token, claims, func(token *jwt.Token) (interface{}, error) {
		if err != nil {
			return publicKey, err
		}
		return publicKey, nil
	})
	log.Println(claims)
}
func V(token string) {
	sampleSecretKey := loadRsaPublicKey()
	publicKey, err := jwt.ParseRSAPublicKeyFromPEM(sampleSecretKey)
	if err != nil {
		log.Println(err)
	}

	claims := jwt.MapClaims{}
	_, err = jwt.ParseWithClaims(token, claims, func(token *jwt.Token) (interface{}, error) {
		if err != nil {
			log.Println(err.Error())
		}
		return publicKey, nil
	})
	if err != nil {
		log.Println(err.Error())
	}
	log.Println(claims)
}

func loadRsaPrivateKey() []byte {
	bytes, err := ioutil.ReadFile("mots.key")
	if err != nil {
		log.Println(err.Error())
	}
	return bytes
}

func loadRsaPublicKey() []byte {
	bytes, err := ioutil.ReadFile("mots.pub")
	if err != nil {
		log.Println(err.Error())
	}
	return bytes
}

func GenerateKey() {
	reader := rand.Reader
	bitSize := 2048

	privatekey, err := rsa.GenerateKey(reader, bitSize)
	if err != nil {
		log.Println(err.Error())
	}
	publickey := &privatekey.PublicKey
	var privateKeyBytes []byte = x509.MarshalPKCS1PrivateKey(privatekey)
	privateKeyBlock := &pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: privateKeyBytes,
	}
	privatePem, err := os.Create("private.key")
	if err != nil {
		fmt.Printf("error when create private.pem: %s \n", err)
		os.Exit(1)
	}
	err = pem.Encode(privatePem, privateKeyBlock)
	if err != nil {
		fmt.Printf("error when encode private pem: %s \n", err)
		os.Exit(1)
	}

	publicKeyBytes, err := x509.MarshalPKIXPublicKey(publickey)
	if err != nil {
		fmt.Printf("error when dumping publickey: %s \n", err)
		os.Exit(1)
	}
	publicKeyBlock := &pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: publicKeyBytes,
	}
	publicPem, err := os.Create("public.pem")
	if err != nil {
		fmt.Printf("error when create public.pem: %s \n", err)
		os.Exit(1)
	}
	err = pem.Encode(publicPem, publicKeyBlock)
	if err != nil {
		fmt.Printf("error when encode public pem: %s \n", err)
		os.Exit(1)
	}
}
