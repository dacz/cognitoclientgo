/*
Package cognitoclientgo implements authentication against AWS Cognito the same way
as the client browser does.

Use it if you want to write app or cli that has the same access as the
regular registered user to your AWS Cognito User pool. I needed it to obtain
the JWT token to authorize API calls to API Gateway that with Cognito Authorizer.

You don't need the AWS IAM credentials. Currently it doesn't support federated identities.


Credentials

You'll need to specify:
	UserPoolID: <string>
	ClientID:   <string>
	SecretHash: [OPTIONAL if configured with you client app] string
	UserName:   <string>
	Password:   <string>

You can get all these params from AWS web console.


Example usage
	c, err := cognitoclientgo.NewClient(auth.Input{
		UserPoolID: os.Getenv("COGNITO_USER_POOL_ID"),
		ClientID:   os.Getenv("COGNITO_CLIENT_ID"),
		SecretHash: os.Getenv("COGNITO_SECRET_HASH"),
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
*/
package cognitoclientgo
