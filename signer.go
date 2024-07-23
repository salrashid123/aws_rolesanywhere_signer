// Provides a Signer for AWS Credential based on RolesAnywhere
//
// Currently, the only way to use a roles anywhere credential in an aws SDK is to use
// a process credential provided by https://github.com/aws/rolesanywhere-credential-helper
//
// Note, a large chunk of this is from https://github.com/aws/rolesanywhere-credential-helper

package rolesanywhere

import (
	"bytes"
	"crypto"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"io"
	"net/http"
	"sort"
	"strings"
	"time"

	awsv1 "github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/request"
)

const (
	aws4_x509_rsa_sha256   = "AWS4-X509-RSA-SHA256"
	aws4_x509_ecdsa_sha256 = "AWS4-X509-ECDSA-SHA256"
	timeFormat             = "20060102T150405Z"
	shortTimeFormat        = "20060102"
	x_amz_date             = "X-Amz-Date"
	x_amz_x509             = "X-Amz-X509"
	x_amz_x509_chain       = "X-Amz-X509-Chain"
	x_amz_content_sha256   = "X-Amz-Content-Sha256"
	authorization          = "Authorization"
	host                   = "Host"
	emptyStringSHA256      = `e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855`
)

// defines the core configuration parameters
type SignerProvider struct {
	CredentialsOpts               // defines the RolesAnywhere configuration setting
	Signer          crypto.Signer // a crypto.Signer implementation
}

type signerCredentialsProvider struct {
	signer crypto.Signer
	CredentialsOpts
	expiration time.Time
}

// Obtain the date-time, formatted as specified by SigV4
func (signerParams *signerParams) getFormattedSigningDateTime() string {
	return signerParams.OverriddenDate.UTC().Format(timeFormat)
}

// Obtain the short date-time, formatted as specified by SigV4
func (signerParams *signerParams) getFormattedShortSigningDateTime() string {
	return signerParams.OverriddenDate.UTC().Format(shortTimeFormat)
}

// Obtain the scope as part of the SigV4-X509 signature
func (signerParams *signerParams) getScope() string {
	var scopeStringBuilder strings.Builder
	scopeStringBuilder.WriteString(signerParams.getFormattedShortSigningDateTime())
	scopeStringBuilder.WriteString("/")
	scopeStringBuilder.WriteString(signerParams.RegionName)
	scopeStringBuilder.WriteString("/")
	scopeStringBuilder.WriteString(signerParams.ServiceName)
	scopeStringBuilder.WriteString("/")
	scopeStringBuilder.WriteString("aws4_request")
	return scopeStringBuilder.String()
}

// Convert certificate to string, so that it can be present in the HTTP request header
func certificateToString(certificate *x509.Certificate) string {
	return base64.StdEncoding.EncodeToString(certificate.Raw)
}

func certificateChainToString(certificateChain []*x509.Certificate) string {
	var x509ChainString strings.Builder
	for i, certificate := range certificateChain {
		x509ChainString.WriteString(certificateToString(certificate))
		if i != len(certificateChain)-1 {
			x509ChainString.WriteString(",")
		}
	}
	return x509ChainString.String()
}

func calculateContentHash(r *http.Request, body io.ReadSeeker) string {
	hash := r.Header.Get(x_amz_content_sha256)

	if hash == "" {
		if body == nil {
			hash = emptyStringSHA256
		} else {
			hash = hex.EncodeToString(makeSha256Reader(body))
		}
	}

	return hash
}

func makeSha256Reader(reader io.ReadSeeker) []byte {
	hash := sha256.New()
	start, _ := reader.Seek(0, 1)
	defer reader.Seek(start, 0)

	io.Copy(hash, reader)
	return hash.Sum(nil)
}

func createCanonicalQueryString(r *http.Request, body io.ReadSeeker) string {
	rawQuery := strings.Replace(r.URL.Query().Encode(), "+", "%20", -1)
	return rawQuery
}

var ignoredHeaderKeys = map[string]bool{
	"Authorization":   true,
	"User-Agent":      true,
	"X-Amzn-Trace-Id": true,
}

const doubleSpace = "  "

// stripExcessSpaces will rewrite the passed in slice's string values to not
// contain muliple side-by-side spaces.
func stripExcessSpaces(vals []string) {
	var j, k, l, m, spaces int
	for i, str := range vals {
		// Trim trailing spaces
		for j = len(str) - 1; j >= 0 && str[j] == ' '; j-- {
		}

		// Trim leading spaces
		for k = 0; k < j && str[k] == ' '; k++ {
		}
		str = str[k : j+1]

		// Strip multiple spaces.
		j = strings.Index(str, doubleSpace)
		if j < 0 {
			vals[i] = str
			continue
		}

		buf := []byte(str)
		for k, m, l = j, j, len(buf); k < l; k++ {
			if buf[k] == ' ' {
				if spaces == 0 {
					// First space.
					buf[m] = buf[k]
					m++
				}
				spaces++
			} else {
				// End of multiple spaces.
				spaces = 0
				buf[m] = buf[k]
				m++
			}
		}

		vals[i] = string(buf[:m])
	}
}

func createCanonicalHeaderString(r *http.Request) (string, string) {
	var headers []string
	signedHeaderVals := make(http.Header)
	for k, v := range r.Header {
		canonicalKey := http.CanonicalHeaderKey(k)
		if ignoredHeaderKeys[canonicalKey] {
			continue
		}

		lowerCaseKey := strings.ToLower(k)
		if _, ok := signedHeaderVals[lowerCaseKey]; ok {
			// include additional values
			signedHeaderVals[lowerCaseKey] = append(signedHeaderVals[lowerCaseKey], v...)
			continue
		}

		headers = append(headers, lowerCaseKey)
		signedHeaderVals[lowerCaseKey] = v
	}
	sort.Strings(headers)

	headerValues := make([]string, len(headers))
	for i, k := range headers {
		headerValues[i] = k + ":" + strings.Join(signedHeaderVals[k], ",")
	}
	stripExcessSpaces(headerValues)
	return strings.Join(headerValues, "\n"), strings.Join(headers, ";")
}

// Create the canonical request.
func createCanonicalRequest(r *http.Request, body io.ReadSeeker, contentSha256 string) (string, string) {
	var canonicalRequestStrBuilder strings.Builder
	canonicalHeaderString, signedHeadersString := createCanonicalHeaderString(r)
	canonicalRequestStrBuilder.WriteString("POST")
	canonicalRequestStrBuilder.WriteString("\n")
	canonicalRequestStrBuilder.WriteString("/sessions")
	canonicalRequestStrBuilder.WriteString("\n")
	canonicalRequestStrBuilder.WriteString(createCanonicalQueryString(r, body))
	canonicalRequestStrBuilder.WriteString("\n")
	canonicalRequestStrBuilder.WriteString(canonicalHeaderString)
	canonicalRequestStrBuilder.WriteString("\n\n")
	canonicalRequestStrBuilder.WriteString(signedHeadersString)
	canonicalRequestStrBuilder.WriteString("\n")
	canonicalRequestStrBuilder.WriteString(contentSha256)
	canonicalRequestString := canonicalRequestStrBuilder.String()
	canonicalRequestStringHashBytes := sha256.Sum256([]byte(canonicalRequestString))
	return hex.EncodeToString(canonicalRequestStringHashBytes[:]), signedHeadersString
}

// Create the string to sign.
func createStringToSign(canonicalRequest string, signerParams signerParams) string {
	var stringToSignStrBuilder strings.Builder
	stringToSignStrBuilder.WriteString(signerParams.SigningAlgorithm)
	stringToSignStrBuilder.WriteString("\n")
	stringToSignStrBuilder.WriteString(signerParams.getFormattedSigningDateTime())
	stringToSignStrBuilder.WriteString("\n")
	stringToSignStrBuilder.WriteString(signerParams.getScope())
	stringToSignStrBuilder.WriteString("\n")
	stringToSignStrBuilder.WriteString(canonicalRequest)
	stringToSign := stringToSignStrBuilder.String()
	return stringToSign
}

// Builds the complete authorization header
func buildAuthorizationHeader(request *http.Request, body io.ReadSeeker, signedHeadersString string, signature string, certificate *x509.Certificate, signerParams signerParams) string {
	signingCredentials := certificate.SerialNumber.String() + "/" + signerParams.getScope()
	credential := "Credential=" + signingCredentials
	signerHeaders := "SignedHeaders=" + signedHeadersString
	signatureHeader := "Signature=" + signature

	var authHeaderStringBuilder strings.Builder
	authHeaderStringBuilder.WriteString(signerParams.SigningAlgorithm)
	authHeaderStringBuilder.WriteString(" ")
	authHeaderStringBuilder.WriteString(credential)
	authHeaderStringBuilder.WriteString(", ")
	authHeaderStringBuilder.WriteString(signerHeaders)
	authHeaderStringBuilder.WriteString(", ")
	authHeaderStringBuilder.WriteString(signatureHeader)
	authHeaderString := authHeaderStringBuilder.String()
	return authHeaderString
}

func encodeDer(der []byte) (string, error) {
	var buf bytes.Buffer
	encoder := base64.NewEncoder(base64.StdEncoding, &buf)
	encoder.Write(der)
	encoder.Close()
	return buf.String(), nil
}

func createRequestSignFunction(signer crypto.Signer, signingAlgorithm string, certificate *x509.Certificate, certificateChain []*x509.Certificate, date time.Time) func(*request.Request) {
	return func(req *request.Request) {
		region := req.ClientInfo.SigningRegion
		if region == "" {
			region = awsv1.StringValue(req.Config.Region)
		}

		name := req.ClientInfo.SigningName
		if name == "" {
			name = req.ClientInfo.ServiceName
		}

		if date.IsZero() {
			date = time.Now()
		}
		signerParams := signerParams{date, region, name, signingAlgorithm}

		// Set headers that are necessary for signing
		req.HTTPRequest.Header.Set(host, req.HTTPRequest.URL.Host)
		req.HTTPRequest.Header.Set(x_amz_date, signerParams.getFormattedSigningDateTime())
		req.HTTPRequest.Header.Set(x_amz_x509, certificateToString(certificate))
		if certificateChain != nil {
			req.HTTPRequest.Header.Set(x_amz_x509_chain, certificateChainToString(certificateChain))
		}

		contentSha256 := calculateContentHash(req.HTTPRequest, req.Body)
		if req.HTTPRequest.Header.Get(x_amz_content_sha256) == "required" {
			req.HTTPRequest.Header.Set(x_amz_content_sha256, contentSha256)
		}

		canonicalRequest, signedHeadersString := createCanonicalRequest(req.HTTPRequest, req.Body, contentSha256)

		stringToSign := createStringToSign(canonicalRequest, signerParams)

		h := sha256.New()
		h.Write([]byte(stringToSign))
		signatureBytes, err := signer.Sign(rand.Reader, h.Sum(nil), crypto.SHA256)
		if err != nil {
			fmt.Printf("error signing: %v\n", err.Error())
			// todo: find a way to return this error to the caller
			return //os.Exit(1)
		}
		signature := hex.EncodeToString(signatureBytes)

		req.HTTPRequest.Header.Set(authorization, buildAuthorizationHeader(req.HTTPRequest, req.Body, signedHeadersString, signature, certificate, signerParams))
		req.SignedHeaderVals = req.HTTPRequest.Header
	}
}
