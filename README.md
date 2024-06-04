Demo of Auth0 Authorization Flows
=========================================

- https://auth0.com/docs/get-started/authentication-and-authorization-flow/which-oauth-2-0-flow-should-i-use
- https://auth0.com/docs/get-started/authentication-and-authorization-flow/device-authorization-flow

## Setup

```
$ cat .env
AUTH0_DOMAIN=<auth0-domain>
AUTH0_CLIENT_ID=<client-id>
AUTH0_REDIRECT_URL=http://localhost:3000/callback
# required for authorization flow
CLIENT_SECRET=<client-secret>

$ go run ./cmd/device-auth/main.go login    # starts authorization flow, and saves token in token.json
$ go run ./cmd/device-auth/main.go refresh  # uses refresh token API, to update the token.json
$ go run ./cmd/device-auth/main.go show     # displays token from token.json

```
