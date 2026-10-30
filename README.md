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
