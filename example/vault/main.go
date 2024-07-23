package main

import (
	"context"
	"crypto"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"log"

	"flag"

	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/sts"

	hv "github.com/hashicorp/vault/api"
	rolesanywhere "github.com/salrashid123/aws_rolesanywhere_signer"
)

const ()

var (
	vaultToken  = flag.String("vaultToken", "", "vaultToken")
	vaultHost   = flag.String("vaultHost", "http:localhost:8200", "vault host")
	vaultPolicy = flag.String("vaultPolicy", "pki/issue/domain-dot-com", "vault policy name")
	vaultCN     = flag.String("vaultCN", "alice-cert.domain.com", "cn for the cert to request")

	bundlePath = flag.String("bundlePath", "", "x509 certificate bundle")

	awsRegion      = flag.String("awsRegion", "us-east-2", "AWS Region")
	roleARN        = flag.String("roleARN", "arn:aws:iam::291738886548:role/rolesanywhere1", "Role to assume")
	trustAnchorARN = flag.String("trustAnchorARN", "arn:aws:rolesanywhere:us-east-2:291738886548:trust-anchor/b48a0464-de03-47a5-83f5-20f5a7a7b375", "Trust Anchor ARN")
	profileARN     = flag.String("profileARN", "arn:aws:rolesanywhere:us-east-2:291738886548:profile/6f4943fb-13d4-4242-89c4-be367595c380", "Profile ARN")
)

func main() {
	flag.Parse()

	// ***************************************************************************

	hvconfig := &hv.Config{
		Address: *vaultHost,
	}

	hclient, err := hv.NewClient(hvconfig)
	if err != nil {
		log.Printf("Unable to initialize vault client: %v", err)
		return
	}

	hclient.SetToken(*vaultToken)

	// vaultTokenSecret, err := client.Auth().Token().LookupSelf()
	// if err != nil {
	// 	log.Printf("VaultToken: cannot lookup token details: %v", err)
	// 	return
	// }

	data := map[string]interface{}{
		"common_name": *vaultCN,
	}

	secret, err := hclient.Logical().Write(*vaultPolicy, data)
	if err != nil {
		log.Printf("VaultToken: cannot read vault secret %v", err)
		return
	}

	d := secret.Data
	publicCert := d["certificate"].(string)
	caPEM := d["issuing_ca"].(string)
	privateKey := d["private_key"].(string)

	log.Printf("cA from vault %s\n", caPEM)
	log.Printf("cert from vault %s\n", publicCert)
	log.Printf("key from vault %s\n", privateKey)
	///

	var chain []*x509.Certificate
	block, _ := pem.Decode([]byte(publicCert))

	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		log.Printf("error reading certificate %v", err)
		return
	}

	block, _ = pem.Decode([]byte(privateKey))
	parseResult, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		log.Printf("error reading private key %v", err)
		return
	}

	var key crypto.Signer

	key = parseResult

	sessionCredentials, err := rolesanywhere.NewAWSRolesAnywhereSignerCredentials(rolesanywhere.SignerProvider{
		CredentialsOpts: rolesanywhere.CredentialsOpts{
			Region:            *awsRegion,
			RoleArn:           *roleARN,
			TrustAnchorArnStr: *trustAnchorARN,
			ProfileArnStr:     *profileARN,
			Certificate:       cert,
			CertificateChain:  chain,
			Debug:             false,
		},
		Signer: key,
	})
	if err != nil {
		fmt.Printf("Could not initialize TPM Credentials %v\n", err)
		return
	}

	ctx := context.Background()

	// *******************************************

	fmt.Println("-------------------------------- GetCallerIdentity with SessionToken SDK")

	cfg, err := config.LoadDefaultConfig(context.TODO(), config.WithRegion(*awsRegion), config.WithCredentialsProvider(sessionCredentials))
	if err != nil {
		fmt.Printf("Could not read GetCallerIdentity response %v", err)
		return
	}

	// if you want to output the same thing a process credential does:
	// c, err := cfg.Credentials.Retrieve(context.Background())
	// if err != nil {
	// 	fmt.Printf("Could not read credentials %v", err)
	// 	return
	// }

	// type CredentialProcessOutput struct {
	// 	// This field should be hard-coded to 1 for now.
	// 	Version int `json:"Version"`
	// 	// AWS Access Key ID
	// 	AccessKeyId string `json:"AccessKeyId"`
	// 	// AWS Secret Access Key
	// 	SecretAccessKey string `json:"SecretAccessKey"`
	// 	// AWS Session Token for temporary credentials
	// 	SessionToken string `json:"SessionToken"`
	// 	// ISO8601 timestamp for when the credentials expire
	// 	Expiration string `json:"Expiration"`
	// }

	// credentialProcessOutput := CredentialProcessOutput{
	// 	Version:         1,
	// 	AccessKeyId:     c.AccessKeyID,
	// 	SecretAccessKey: c.SecretAccessKey,
	// 	SessionToken:    c.SessionToken,
	// 	Expiration:      c.Expires.Format(time.RFC3339),
	// }
	// bb, err := json.MarshalIndent(credentialProcessOutput, "", "  ")
	// if err != nil {
	// 	fmt.Println(err)
	// }
	// fmt.Print(string(bb))

	stssvc := sts.NewFromConfig(cfg, func(o *sts.Options) {
		o.Region = *awsRegion
	})

	stsresp, err := stssvc.GetCallerIdentity(ctx, &sts.GetCallerIdentityInput{})
	if err != nil {
		fmt.Printf("Could not read GetCallerIdentity response %v\n", err)
		return
	}
	fmt.Printf("STS Identity from API %s\n", *stsresp.UserId)

	// s3Client := s3.NewFromConfig(cfg)

	// output, err := s3Client.ListBuckets(context.TODO(), &s3.ListBucketsInput{})
	// if err != nil {
	// 	panic(err.Error())
	// }

	// for index, bucket := range output.Buckets {
	// 	fmt.Printf("Bucket %v: %v\n", index+1, *bucket.Name)
	// }

}
