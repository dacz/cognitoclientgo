# cognitoclientgo [![GoDoc](https://godoc.org/github.com/dacz/cognitoclientgo?status.png)](https://godoc.org/github.com/dacz/cognitoclientgo) [![Go Report Card](https://goreportcard.com/badge/github.com/dacz/cognitoclientgo)](https://goreportcard.com/report/github.com/dacz/cognitoclientgo) [![Build](https://travis-ci.org/dacz/cognitoclientgo.svg?branch=master)](https://travis-ci.org/dacz/cognitoclientgo)

Implements authentication against AWS Cognito the same way
as the client browser does (so you don't need the AWS IAM credentials to call the API).

Use `client.Auth()` before all requests. If client has a valid and fresh tokens it uses them. If client holds refresh token, it uses this one to get new JWT token and for the first time or after even refresh token expires it uses full SRP auth.

Use it if you want to write app or cli that has the same access as the
regular registered user to your AWS Cognito User pool. I needed it to obtain
the JWT token to authorize API calls to API Gateway that with Cognito Authorizer.

It doesn't support federated identities for now.

## Usage

`import "github.com/dacz/cognitoclientgo"`

Example usage

```golang
	c, err := cognitoclientgo.NewClient(client.Input{
		UserPoolID: os.Getenv("COGNITO_USER_POOL_ID"),
		ClientID:   os.Getenv("COGNITO_CLIENT_ID"),
		SecretHash: os.Getenv("COGNITO_SECRET_HASH"), // OPTIONAL if configured with you client app
		UserName:   os.Getenv("COGNITO_USERNAME"),
		Password:   os.Getenv("COGNITO_PASSWORD"),
	})
	if err != nil {
		...
	}

	// jwtToken can be used in Authorization header sent to API GW
	jwtToken, err := c.Auth()
	if err != nil {
		...
	}

	// once authorized you can call getUser to get info about user from Cognito
	user, err := c.GetUser()
	if err != nil {
		...
    }
```

## Credits

SRP package: Alex Rudd (https://github.com/AlexRudd/cognito-srp) - lightly modified.

## LICENSE

MIT (see [license file](./LICENSE))
