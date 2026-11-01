# Dbrij Secrets for Go

Load your app's secrets from Dbrij Secrets with a machine token, and open them on your own server. Dbrij stores only what it cannot open.

```bash
go get github.com/SAW-TECHNOLOGIES-LIMITED/Dbrij/packages/secrets-go
```

```go
import dbrijsecrets "github.com/SAW-TECHNOLOGIES-LIMITED/Dbrij/packages/secrets-go"

// Reads DBRIJ_SECRETS_TOKEN and DBRIJ_SECRETS_ENV from the environment.
secrets, err := dbrijsecrets.New(dbrijsecrets.Options{Environment: "production"})
if err != nil {
	log.Fatal(err)
}
if _, err := secrets.Load(ctx); err != nil {
	log.Fatal(err)
}
databaseURL, _ := secrets.Get("DATABASE_URL")
secrets.InjectEnv(true) // or put every value into the process environment
```

- `Refresh` asks with the last ETag, so an unchanged environment costs one small request.
- If Dbrij cannot be reached, the last good copy is served for `Options.FailSoft` (one hour by default). A refusal, such as a revoked token, is never hidden.
- `Version()` and `Project()` give the environment version and the project the values came from, once loaded.
- `Watch(ctx, onChange, onError)` follows the environment's version stream and calls you when values change, until `ctx` is done.
- A machine with write access can `Set` and `Delete`. Values are sealed here before they leave, and a save is refused if the environment changed since the copy it started from (it reloads and tries once more).
- A login key (`dbsk_...`) in `DBRIJ_SECRETS_KEY` logs in with the identity the machine already has: GitHub Actions (give the job `permissions: id-token: write`), AWS, Google Cloud, Azure or Kubernetes. Dbrij says which, and the SDK fetches the proof itself.

Only the first two parts of a token are ever sent to Dbrij. Go 1.24 or newer, standard library only, safe for use by several goroutines.

## Key management

Use a Dbrij Secrets Key management key with the same machine token, once the key's page gives this machine the operations it needs. The key never leaves Dbrij.

```go
keys := client.Keys()
ct, err := keys.Encrypt(ctx, keyID, []byte("a customer BVN"), map[string]string{"table": "customers"})
bvn, err := keys.Decrypt(ctx, keyID, ct.Ciphertext, map[string]string{"table": "customers"})

// Larger than 4 KB: a data key from Dbrij, AES 256 GCM on this server.
sealed, err := keys.EncryptLarge(ctx, keyID, bigFile, nil)
back, err := keys.DecryptLarge(ctx, keyID, sealed, nil)

sig, err := keys.Sign(ctx, signingKeyID, manifest)
ok, err := keys.Verify(ctx, signingKeyID, manifest, sig.Signature, 0)
```

Also `NewDataKey`, `Reencrypt`, `Mac`, `VerifyMac` and `PublicKey`. Decrypting needs the same context the value was encrypted with. Envelopes from `EncryptLarge` open in the Node and Python SDKs too.

## Options

| Field | Default |
|---|---|
| `Token` | `DBRIJ_SECRETS_TOKEN`, then `DBRIJ_SECRETS_KEY` |
| `Environment` | `DBRIJ_SECRETS_ENV`, or the only environment the machine reads |
| `Paths` | `["/"]`; folders merged in order, a later one winning |
| `Recursive` | `false`; include the folders inside |
| `BaseURL` | `DBRIJ_API_URL`, then `https://api.dbrij.com/api/v1` |
| `FailSoft` | one hour; negative turns it off |
| `Timeout` | ten seconds per request |
| `HTTPClient` | a plain `http.Client` |

## Tests

```bash
go test -race ./...
```

`testdata/fixture.json` is written by the Node SDK (`node packages/secrets/scripts/python-fixture.mjs`, which writes the Python SDK's copy too), so the tests prove the SDKs open each other's work.
