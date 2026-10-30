package dbrijsecrets

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"
)

var federatedNow = time.Date(2026, 10, 30, 12, 0, 0, 0, time.UTC)

type call struct {
	method, url string
	headers     map[string]string
	body        string
}

type answer struct {
	status int
	body   string
}

func routes(r map[string]answer, calls *[]call) opener {
	return func(_ context.Context, method, url string, headers map[string]string, body string) (int, string, error) {
		if calls != nil {
			*calls = append(*calls, call{method, url, headers, body})
		}
		a, ok := r[url]
		if !ok {
			return 0, "", errors.New("unreachable")
		}
		return a.status, a.body, nil
	}
}

func envOf(m map[string]string) func(string) string { return func(k string) string { return m[k] } }

func TestSignsExactlyAsTheAPINodeAndPythonDo(t *testing.T) {
	h := signAWS(
		"POST",
		"https://sts.eu-west-1.amazonaws.com/",
		map[string]string{"content-type": "application/x-www-form-urlencoded; charset=utf-8", "x-dbrij-secrets-server": "https://secrets.dbrij.com"},
		"Action=GetCallerIdentity&Version=2011-06-15",
		"eu-west-1",
		"sts",
		awsCreds{"AKIDEXAMPLE", "wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY", "tok"},
		federatedNow,
	)
	want := "AWS4-HMAC-SHA256 Credential=AKIDEXAMPLE/20261030/eu-west-1/sts/aws4_request, SignedHeaders=content-type;host;x-amz-date;x-amz-security-token;x-dbrij-secrets-server, Signature=0c2c3441a795538bdcb618fbdcc8aafd97f0272b5a417741d912ef00a80e3509"
	if h["authorization"] != want {
		t.Fatalf("got %s", h["authorization"])
	}
}

func TestAWSSignsForSTSAndSendsNothingItself(t *testing.T) {
	var calls []call
	p, err := platformProof(context.Background(), "aws", "https://secrets.dbrij.com", proofContext{open: routes(nil, &calls), env: envOf(map[string]string{"AWS_ACCESS_KEY_ID": "A", "AWS_SECRET_ACCESS_KEY": "S"}), now: federatedNow})
	if err != nil {
		t.Fatal(err)
	}
	if p.AWS.URL != "https://sts.amazonaws.com/" || p.AWS.Headers["x-dbrij-secrets-server"] != "https://secrets.dbrij.com" || len(calls) != 0 {
		t.Fatalf("proof %+v, calls %d", p.AWS, len(calls))
	}
	regional, _ := platformProof(context.Background(), "aws", "https://secrets.dbrij.com", proofContext{open: routes(nil, nil), env: envOf(map[string]string{"AWS_ACCESS_KEY_ID": "A", "AWS_SECRET_ACCESS_KEY": "S", "AWS_REGION": "eu-west-1"}), now: federatedNow})
	if regional.AWS.URL != "https://sts.eu-west-1.amazonaws.com/" || !strings.Contains(regional.AWS.Headers["authorization"], "/eu-west-1/sts/") {
		t.Fatalf("regional %+v", regional.AWS)
	}
}

func TestAWSCredentialsFromEC2MetadataVersion2(t *testing.T) {
	var calls []call
	r := map[string]answer{
		"http://169.254.169.254/latest/api/token":                                   {200, "imds"},
		"http://169.254.169.254/latest/meta-data/iam/security-credentials/":         {200, "web-role\n"},
		"http://169.254.169.254/latest/meta-data/iam/security-credentials/web-role": {200, `{"AccessKeyId":"B","SecretAccessKey":"S","Token":"T"}`},
	}
	creds, err := awsCredentials(context.Background(), proofContext{open: routes(r, &calls), env: envOf(nil)})
	if err != nil {
		t.Fatal(err)
	}
	if creds.AccessKeyID != "B" || creds.SessionToken != "T" || calls[0].method != "PUT" || calls[1].headers["X-aws-ec2-metadata-token"] != "imds" {
		t.Fatalf("creds %+v calls %+v", creds, calls)
	}
}

func TestAWSCredentialsFromAWebIdentity(t *testing.T) {
	var calls []call
	r := map[string]answer{"https://sts.amazonaws.com/": {200, "<AssumeRoleWithWebIdentityResponse><Credentials><AccessKeyId>W</AccessKeyId><SecretAccessKey>S</SecretAccessKey><SessionToken>T</SessionToken></Credentials></AssumeRoleWithWebIdentityResponse>"}}
	creds, err := awsCredentials(context.Background(), proofContext{
		open:     routes(r, &calls),
		env:      envOf(map[string]string{"AWS_WEB_IDENTITY_TOKEN_FILE": "/token", "AWS_ROLE_ARN": "arn:aws:iam::123456789012:role/app"}),
		readFile: func(string) (string, error) { return "web.token\n", nil },
	})
	if err != nil {
		t.Fatal(err)
	}
	if creds.AccessKeyID != "W" || !strings.Contains(calls[0].body, "WebIdentityToken=web.token") {
		t.Fatalf("creds %+v body %s", creds, calls[0].body)
	}
}

func TestGoogleCloudAzureKubernetes(t *testing.T) {
	ctx := context.Background()
	gcp := "http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/identity?audience=https%3A%2F%2Fsecrets.dbrij.com&format=full"
	if p, err := platformProof(ctx, "gcp", "https://secrets.dbrij.com", proofContext{open: routes(map[string]answer{gcp: {200, "a.b.c\n"}}, nil), env: envOf(nil)}); err != nil || p.Token != "a.b.c" {
		t.Fatalf("gcp %+v %v", p, err)
	}
	az := "http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&client_id=cid&resource=api%3A%2F%2Fdbrij"
	if p, err := platformProof(ctx, "azure", "api://dbrij", proofContext{open: routes(map[string]answer{az: {200, `{"access_token":"x.y.z"}`}}, nil), env: envOf(map[string]string{"AZURE_CLIENT_ID": "cid"})}); err != nil || p.Token != "x.y.z" {
		t.Fatalf("azure %+v %v", p, err)
	}
	app := "http://127.0.0.1:41741/msi/token?api-version=2019-08-01&client_id=cid&resource=api%3A%2F%2Fdbrij"
	var appCalls []call
	if p, err := platformProof(ctx, "azure", "api://dbrij", proofContext{open: routes(map[string]answer{app: {200, `{"access_token":"a.p.p"}`}}, &appCalls), env: envOf(map[string]string{"IDENTITY_ENDPOINT": "http://127.0.0.1:41741/msi/token", "IDENTITY_HEADER": "h", "AZURE_CLIENT_ID": "cid"})}); err != nil || p.Token != "a.p.p" || appCalls[0].headers["X-IDENTITY-HEADER"] != "h" {
		t.Fatalf("app service %+v %v %+v", p, err, appCalls)
	}
	var read string
	k8s := proofContext{open: routes(nil, nil), env: envOf(nil), readFile: func(p string) (string, error) { read = p; return "k.8.s\n", nil }}
	if p, err := platformProof(ctx, "kubernetes", "https://secrets.dbrij.com", k8s); err != nil || p.Token != "k.8.s" || read != "/var/run/secrets/dbrij/token" {
		t.Fatalf("kubernetes %+v %v %s", p, err, read)
	}
	if _, err := platformProof(ctx, "gcp", "https://secrets.dbrij.com", proofContext{open: routes(nil, nil), env: envOf(nil)}); err == nil {
		t.Fatal("off Google Cloud there is no proof")
	}
}

func TestSourceCIAsksWithTheJobRequestToken(t *testing.T) {
	ctx := context.Background()
	target := "https://api.dbrij.com/api/v1/public/source/ci/token?audience=https%3A%2F%2Fsecrets.dbrij.com"
	var calls []call
	env := envOf(map[string]string{"DBRIJ_CI_TOKEN_URL": "https://api.dbrij.com/api/v1/public/source/ci/token", "DBRIJ_CI_REQUEST_TOKEN": "dbci_abc"})
	p, err := platformProof(ctx, "source", "https://secrets.dbrij.com", proofContext{open: routes(map[string]answer{target: {200, `{"value":"s.c.i"}`}}, &calls), env: env})
	if err != nil || p.Token != "s.c.i" || calls[0].headers["Authorization"] != "Bearer dbci_abc" {
		t.Fatalf("source %+v %v %+v", p, err, calls)
	}
	if _, err := platformProof(ctx, "source", "https://secrets.dbrij.com", proofContext{open: routes(nil, nil), env: envOf(nil)}); err == nil {
		t.Fatal("outside a Source CI job there is no proof")
	}
}
