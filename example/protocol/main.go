// script which implements AWS RolesAnywhre Signing Process
//
//		https://docs.aws.amazon.com/rolesanywhere/latest/userguide/authentication-sign-process.html
//
//	 currently only RSA keys are supported but its trivial to change it to ec
//
// for python  see https://nerdydrunk.info/aws:roles_anywhere
//
//	export  GODEBUG=http2debug=2
package main

import (
	"bytes"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"time"

	"flag"
)

const (
	timeFormat      = "20060102T150405Z"
	shortTimeFormat = "20060102"
)

var (
	// RSA
	certPath       = flag.String("certPath", "certs/alice-cert.crt", "x509 certificate")
	privateKey     = flag.String("privateKey", "certs/alice-cert.key", "x509 certificate")
	awsRegion      = flag.String("awsRegion", "us-east-2", "AWS Region")
	roleARN        = flag.String("roleARN", "arn:aws:iam::291738886548:role/rolesanywhere1", "Role to assume")
	trustAnchorARN = flag.String("trustAnchorARN", "arn:aws:rolesanywhere:us-east-2:291738886548:trust-anchor/a545a1fc-5d86-4032-8f4c-61cdd6ff92da", "Trust Anchor ARN")
	profileARN     = flag.String("profileARN", "arn:aws:rolesanywhere:us-east-2:291738886548:profile/6f4943fb-13d4-4242-89c4-be367595c380", "Profile ARN")

	// ECC
	// certPath       = flag.String("certPath", "certs/alice-cert-ecc.crt", "x509 certificate")
	// privateKey     = flag.String("privateKey", "certs/alice-cert-ecc.key", "x509 certificate")
	// awsRegion      = flag.String("awsRegion", "us-east-2", "AWS Region")
	// roleARN        = flag.String("roleARN", "arn:aws:iam::291738886548:role/rolesanywhere1", "Role to assume")
	// trustAnchorARN = flag.String("trustAnchorARN", "arn:aws:rolesanywhere:us-east-2:291738886548:trust-anchor/1cb4e36e-e4ad-4bbb-9b37-fdafb2cbe4fe", "Trust Anchor ARN")
	// profileARN     = flag.String("profileARN", "arn:aws:rolesanywhere:us-east-2:291738886548:profile/6f4943fb-13d4-4242-89c4-be367595c380", "Profile ARN")
)

func main() {
	flag.Parse()

	// ***************************************************************************

	c, err := os.ReadFile(*certPath)
	if err != nil {
		log.Printf("error reading private key %v", err)
		return
	}

	block, _ := pem.Decode(c)

	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		log.Printf("error reading certificate %v", err)
		return
	}

	b, err := os.ReadFile(*privateKey)
	if err != nil {
		log.Printf("error reading private key %v", err)
		return
	}
	blockr, _ := pem.Decode(b)
	parseResult, err := x509.ParsePKCS8PrivateKey(blockr.Bytes)
	if err != nil {
		log.Printf("error reading private key %v", err)
		return
	}

	// RSA
	privateKey := parseResult.(*rsa.PrivateKey)

	//ECC
	//privateKey := parseResult.(*ecdsa.PrivateKey)

	serial_number_dec := cert.SerialNumber.String()

	method := "POST"
	service := "rolesanywhere"
	host := fmt.Sprintf("rolesanywhere.%s.amazonaws.com", *awsRegion)
	endpoint := fmt.Sprintf("https://rolesanywhere.%s.amazonaws.com", *awsRegion)
	content_type := "application/json"

	request_parameters := []byte(fmt.Sprintf(`{"durationSeconds":900,"profileArn":"%s","roleArn":"%s","trustAnchorArn":"%s"}`, *profileARN, *roleARN, *trustAnchorARN))

	now := time.Now().UTC()

	amz_date := now.Format(timeFormat)
	date_stamp := now.Format(shortTimeFormat) //Date w/o time, used in credential scope

	amz_x509 := base64.StdEncoding.EncodeToString(cert.Raw)

	canonical_uri := "/sessions"

	canonical_querystring := ""

	canonical_headers := "content-type:" + content_type + "\n" + "host:" + host + "\n" + "x-amz-date:" + amz_date + "\n" + "x-amz-x509:" + amz_x509 + "\n"

	signed_headers := "content-type;host;x-amz-date;x-amz-x509"

	h1 := sha256.New()
	h1.Write([]byte(request_parameters))
	payload_hash := hex.EncodeToString(h1.Sum(nil))

	canonical_request := method + "\n" + canonical_uri + "\n" + canonical_querystring + "\n" + canonical_headers + "\n" + signed_headers + "\n" + payload_hash

	h2 := sha256.New()
	h2.Write([]byte(canonical_request))
	canonical_request_hash := hex.EncodeToString(h2.Sum(nil))

	// RSA
	algorithm := "AWS4-X509-RSA-SHA256"

	// ECC
	//algorithm := "AWS4-X509-ECDSA-SHA256"

	credential_scope := date_stamp + "/" + *awsRegion + "/" + service + "/" + "aws4_request"
	string_to_sign := algorithm + "\n" + amz_date + "\n" + credential_scope + "\n" + canonical_request_hash

	h3 := sha256.New()
	h3.Write([]byte(string_to_sign))

	// RSA
	signature, err := rsa.SignPKCS1v15(rand.Reader, privateKey, crypto.SHA256, h3.Sum(nil))
	if err != nil {
		fmt.Println(err)
		return
	}

	// ECC
	// signature, err := ecdsa.SignASN1(rand.Reader, privateKey, h3.Sum(nil))
	// if err != nil {
	// 	fmt.Println(err)
	// 	return
	// }

	signature_hex := hex.EncodeToString(signature)

	authorization_header := algorithm + " " + "Credential=" + serial_number_dec + "/" + credential_scope + ", " + "SignedHeaders=" + signed_headers + ", " + "Signature=" + signature_hex

	client := &http.Client{}

	req, err := http.NewRequest(method, endpoint+canonical_uri+canonical_querystring, bytes.NewBuffer(request_parameters))
	if err != nil {
		fmt.Println(err)
		return
	}

	req.Header.Set("Host", host)
	req.Header.Set("Content-Type", content_type)
	req.Header.Set("X-Amz-Date", amz_date)
	req.Header.Set("X-Amz-X509", amz_x509)
	req.Header.Set("Authorization", authorization_header)

	resp, err := client.Do(req)
	if err != nil {
		fmt.Println(err)
		return
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		fmt.Println(err)
		return
	}

	fmt.Println(string(body))

}
