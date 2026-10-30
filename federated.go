package dbrijsecrets

// Logging in with the identity a platform gives the machine (AWS, Google Cloud, Azure,
// Kubernetes): the same proofs as the Node SDK (federated.ts) and the Python SDK, each
// from its platform's own documentation. Standard library only.

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"sort"
	"strings"
	"time"
)

const (
	awsServerHeader            = "x-dbrij-secrets-server"
	getCallerIdentityBody      = "Action=GetCallerIdentity&Version=2011-06-15"
	defaultKubernetesTokenFile = "/var/run/secrets/dbrij/token"
)

// opener sends one request to a metadata service or AWS: (status, body). It is replaced in
// tests. An error means the service could not be reached: not on that platform.
type opener func(ctx context.Context, method, url string, headers map[string]string, body string) (int, string, error)

func httpOpener(client *http.Client) opener {
	return func(ctx context.Context, method, target string, headers map[string]string, body string) (int, string, error) {
		var reader io.Reader
		if body != "" {
			reader = strings.NewReader(body)
		}
		req, err := http.NewRequestWithContext(ctx, method, target, reader)
		if err != nil {
			return 0, "", err
		}
		for k, v := range headers {
			req.Header.Set(k, v)
		}
		res, err := client.Do(req)
		if err != nil {
			return 0, "", err
		}
		defer res.Body.Close()
		text, err := io.ReadAll(io.LimitReader(res.Body, 1<<20))
		if err != nil {
			return 0, "", err
		}
		return res.StatusCode, string(text), nil
	}
}

// awsRequest is a GetCallerIdentity request signed here, never sent to AWS by us: Dbrij
// sends it, and AWS answers who signed it.
type awsRequest struct {
	URL     string            `json:"url"`
	Method  string            `json:"method"`
	Headers map[string]string `json:"headers"`
	Body    string            `json:"body"`
}

// proof is what a federated login sends: a platform's token, or for AWS a signed request.
type proof struct {
	Token string      `json:"token,omitempty"`
	AWS   *awsRequest `json:"aws,omitempty"`
}

type proofContext struct {
	open     opener
	env      func(string) string
	readFile func(string) (string, error)
	now      time.Time
}

func defaultProofContext(client *http.Client) proofContext {
	return proofContext{
		open: httpOpener(client),
		env:  os.Getenv,
		readFile: func(path string) (string, error) {
			b, err := os.ReadFile(path)
			return string(b), err
		},
	}
}

func platformProof(ctx context.Context, kind, audience string, pc proofContext) (proof, error) {
	switch kind {
	case "gcp":
		target := "http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/identity?" + url.Values{"audience": {audience}, "format": {"full"}}.Encode()
		status, text := safe(ctx, pc.open, "GET", target, map[string]string{"Metadata-Flavor": "Google"}, "")
		if status != 200 {
			return proof{}, fmt.Errorf("Google Cloud's metadata server gave no identity token (%d). Run this on Google Cloud with a service account attached", status)
		}
		return proof{Token: strings.TrimSpace(text)}, nil
	case "azure":
		q := url.Values{"resource": {audience}}
		if id := pc.env("AZURE_CLIENT_ID"); id != "" {
			q.Set("client_id", id)
		}
		target, headers := "", map[string]string{}
		if endpoint, header := pc.env("IDENTITY_ENDPOINT"), pc.env("IDENTITY_HEADER"); endpoint != "" && header != "" {
			// App Service and Functions run their own token service, named in the environment.
			q.Set("api-version", "2019-08-01")
			sep := "?"
			if strings.Contains(endpoint, "?") {
				sep = "&"
			}
			target, headers["X-IDENTITY-HEADER"] = endpoint+sep+q.Encode(), header
		} else {
			q.Set("api-version", "2018-02-01")
			target, headers["Metadata"] = "http://169.254.169.254/metadata/identity/oauth2/token?"+q.Encode(), "true"
		}
		status, text := safe(ctx, pc.open, "GET", target, headers, "")
		if status != 200 {
			return proof{}, fmt.Errorf("Azure's instance metadata service gave no managed identity token (%d). Check the identity is attached and %s is an app in its tenant", status, audience)
		}
		var body struct {
			AccessToken string `json:"access_token"`
		}
		if json.Unmarshal([]byte(text), &body) != nil || body.AccessToken == "" {
			return proof{}, errors.New("Azure answered without a token")
		}
		return proof{Token: body.AccessToken}, nil
	case "source":
		target, requestToken := pc.env("DBRIJ_CI_TOKEN_URL"), pc.env("DBRIJ_CI_REQUEST_TOKEN")
		if target == "" || requestToken == "" {
			return proof{}, errors.New("this key logs in from Dbrij Source CI. Run it inside a Source CI job")
		}
		sep := "?"
		if strings.Contains(target, "?") {
			sep = "&"
		}
		status, text := safe(ctx, pc.open, "GET", target+sep+url.Values{"audience": {audience}}.Encode(), map[string]string{"Authorization": "Bearer " + requestToken}, "")
		if status != 200 {
			return proof{}, fmt.Errorf("Source CI gave no identity token (%d). It is given only while the job runs", status)
		}
		var body struct {
			Value string `json:"value"`
		}
		if json.Unmarshal([]byte(text), &body) != nil || body.Value == "" {
			return proof{}, errors.New("Source CI answered without a token")
		}
		return proof{Token: body.Value}, nil
	case "kubernetes":
		path := pc.env("DBRIJ_SECRETS_KUBERNETES_TOKEN_FILE")
		if path == "" {
			path = defaultKubernetesTokenFile
		}
		text, err := pc.readFile(path)
		token := strings.TrimSpace(text)
		if err != nil || token == "" {
			return proof{}, fmt.Errorf("no service account token at %s. Project one with audience %s there (or set DBRIJ_SECRETS_KUBERNETES_TOKEN_FILE)", path, audience)
		}
		return proof{Token: token}, nil
	case "aws":
		creds, err := awsCredentials(ctx, pc)
		if err != nil {
			return proof{}, err
		}
		region := pc.env("AWS_REGION")
		if region == "" {
			region = pc.env("AWS_DEFAULT_REGION")
		}
		target := "https://sts.amazonaws.com/"
		signRegion := "us-east-1"
		if region != "" {
			target = "https://sts." + region + ".amazonaws.com/"
			signRegion = region
		}
		now := pc.now
		if now.IsZero() {
			now = time.Now()
		}
		headers := signAWS("POST", target, map[string]string{"content-type": "application/x-www-form-urlencoded; charset=utf-8", awsServerHeader: audience}, getCallerIdentityBody, signRegion, "sts", creds, now)
		return proof{AWS: &awsRequest{URL: target, Method: "POST", Headers: headers, Body: getCallerIdentityBody}}, nil
	}
	return proof{}, fmt.Errorf("this SDK cannot log in from %s", kind)
}

func safe(ctx context.Context, open opener, method, target string, headers map[string]string, body string) (int, string) {
	status, text, err := open(ctx, method, target, headers, body)
	if err != nil {
		return 0, ""
	}
	return status, text
}

type awsCreds struct {
	AccessKeyID     string
	SecretAccessKey string
	SessionToken    string
}

var xmlTag = func(tag, xml string) string {
	m := regexp.MustCompile("<" + tag + ">([^<]+)</" + tag + ">").FindStringSubmatch(xml)
	if m == nil {
		return ""
	}
	return m[1]
}

// awsCredentials finds the machine's AWS credentials in the usual places, in the usual
// order: the environment, a container endpoint (ECS), a web identity (EKS), then EC2's
// instance metadata service version 2.
func awsCredentials(ctx context.Context, pc proofContext) (awsCreds, error) {
	if id, secret := pc.env("AWS_ACCESS_KEY_ID"), pc.env("AWS_SECRET_ACCESS_KEY"); id != "" && secret != "" {
		return awsCreds{id, secret, pc.env("AWS_SESSION_TOKEN")}, nil
	}
	if rel, full := pc.env("AWS_CONTAINER_CREDENTIALS_RELATIVE_URI"), pc.env("AWS_CONTAINER_CREDENTIALS_FULL_URI"); rel != "" || full != "" {
		target := full
		if rel != "" {
			target = "http://169.254.170.2" + rel
		}
		headers := map[string]string{}
		if auth := pc.env("AWS_CONTAINER_AUTHORIZATION_TOKEN"); auth != "" {
			headers["Authorization"] = auth
		}
		status, text := safe(ctx, pc.open, "GET", target, headers, "")
		if status != 200 {
			return awsCreds{}, fmt.Errorf("the container credentials endpoint answered %d", status)
		}
		return fromAWSJSON(text)
	}
	if tokenFile, roleARN := pc.env("AWS_WEB_IDENTITY_TOKEN_FILE"), pc.env("AWS_ROLE_ARN"); tokenFile != "" && roleARN != "" {
		webToken, err := pc.readFile(tokenFile)
		if err != nil {
			return awsCreds{}, fmt.Errorf("could not read the web identity token: %w", err)
		}
		session := pc.env("AWS_ROLE_SESSION_NAME")
		if session == "" {
			session = "dbrij-secrets"
		}
		body := url.Values{"Action": {"AssumeRoleWithWebIdentity"}, "Version": {"2011-06-15"}, "RoleArn": {roleARN}, "RoleSessionName": {session}, "WebIdentityToken": {strings.TrimSpace(webToken)}}.Encode()
		status, xml := safe(ctx, pc.open, "POST", "https://sts.amazonaws.com/", map[string]string{"content-type": "application/x-www-form-urlencoded"}, body)
		if status != 200 || xmlTag("AccessKeyId", xml) == "" {
			code := xmlTag("Code", xml)
			if code == "" {
				code = fmt.Sprint(status)
			}
			return awsCreds{}, fmt.Errorf("AWS did not exchange the web identity token (%s)", code)
		}
		return awsCreds{xmlTag("AccessKeyId", xml), xmlTag("SecretAccessKey", xml), xmlTag("SessionToken", xml)}, nil
	}
	status, imds := safe(ctx, pc.open, "PUT", "http://169.254.169.254/latest/api/token", map[string]string{"X-aws-ec2-metadata-token-ttl-seconds": "300"}, "")
	if status != 200 {
		return awsCreds{}, errors.New("no AWS credentials found: set AWS_ACCESS_KEY_ID and AWS_SECRET_ACCESS_KEY, or run on AWS with a role attached")
	}
	auth := map[string]string{"X-aws-ec2-metadata-token": imds}
	status, names := safe(ctx, pc.open, "GET", "http://169.254.169.254/latest/meta-data/iam/security-credentials/", auth, "")
	role := ""
	if status == 200 {
		role = strings.TrimSpace(strings.SplitN(names, "\n", 2)[0])
	}
	if role == "" {
		return awsCreds{}, errors.New("this instance has no IAM role attached")
	}
	status, text := safe(ctx, pc.open, "GET", "http://169.254.169.254/latest/meta-data/iam/security-credentials/"+url.PathEscape(role), auth, "")
	if status != 200 {
		return awsCreds{}, fmt.Errorf("the instance metadata service answered %d", status)
	}
	return fromAWSJSON(text)
}

func fromAWSJSON(text string) (awsCreds, error) {
	var j struct {
		AccessKeyID     string `json:"AccessKeyId"`
		SecretAccessKey string `json:"SecretAccessKey"`
		Token           string `json:"Token"`
	}
	if json.Unmarshal([]byte(text), &j) != nil || j.AccessKeyID == "" || j.SecretAccessKey == "" {
		return awsCreds{}, errors.New("AWS answered without credentials")
	}
	return awsCreds{j.AccessKeyID, j.SecretAccessKey, j.Token}, nil
}

var spaces = regexp.MustCompile(`\s+`)

func hmacSHA256(key []byte, data string) []byte {
	m := hmac.New(sha256.New, key)
	m.Write([]byte(data))
	return m.Sum(nil)
}

func sha256Hex(data string) string {
	sum := sha256.Sum256([]byte(data))
	return hex.EncodeToString(sum[:])
}

// signAWS gives Signature Version 4 headers: the same bytes as the API's, the Node SDK's
// and the Python SDK's signers for the same request.
func signAWS(method, target string, headers map[string]string, body, region, service string, creds awsCreds, now time.Time) map[string]string {
	u, _ := url.Parse(target)
	amzDate := now.UTC().Format("20060102T150405Z")
	day := amzDate[:8]
	h := map[string]string{}
	for k, v := range headers {
		h[strings.ToLower(k)] = spaces.ReplaceAllString(strings.TrimSpace(v), " ")
	}
	h["host"] = u.Host
	h["x-amz-date"] = amzDate
	if creds.SessionToken != "" {
		h["x-amz-security-token"] = creds.SessionToken
	}
	names := make([]string, 0, len(h))
	for n := range h {
		names = append(names, n)
	}
	sort.Strings(names)
	var canonicalHeaders strings.Builder
	for _, n := range names {
		canonicalHeaders.WriteString(n + ":" + h[n] + "\n")
	}
	path := u.Path
	if path == "" {
		path = "/"
	}
	signed := strings.Join(names, ";")
	canonical := strings.Join([]string{method, path, "", canonicalHeaders.String(), signed, sha256Hex(body)}, "\n")
	scope := day + "/" + region + "/" + service + "/aws4_request"
	toSign := strings.Join([]string{"AWS4-HMAC-SHA256", amzDate, scope, sha256Hex(canonical)}, "\n")
	key := []byte("AWS4" + creds.SecretAccessKey)
	for _, part := range []string{day, region, service, "aws4_request"} {
		key = hmacSHA256(key, part)
	}
	signature := hex.EncodeToString(hmacSHA256(key, toSign))
	h["authorization"] = "AWS4-HMAC-SHA256 Credential=" + creds.AccessKeyID + "/" + scope + ", SignedHeaders=" + signed + ", Signature=" + signature
	return h
}
