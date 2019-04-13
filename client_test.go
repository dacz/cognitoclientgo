package cognitoclientgo

import (
	"fmt"
	"os"
	"testing"
	"time"

	"github.com/joho/godotenv"
)

func TestNewClient_ok(t *testing.T) {
	testCasesOk := []Input{
		{
			UserPoolID: "eu-west-1_someid1",
			ClientID:   "someclientid",
			SecretHash: "somesecrethash",
			UserName:   "someusername",
			Password:   "somepassword",
		},
		{
			UserPoolID: "eu-west-1_someid2",
			ClientID:   "someclientid",
			UserName:   "someusername",
			Password:   "somepassword",
		},
	}
	for _, tc := range testCasesOk {
		t.Run(fmt.Sprintf("%v", tc.UserPoolID), func(t *testing.T) {
			_, err := NewClient(tc)
			if err != nil {
				t.Fatalf("should not return error, but: %v", err.Error())
			}
		})
	}
}

func TestNewClient_fail(t *testing.T) {
	testCasesOk := []Input{
		{
			UserPoolID: "eu-west-1someid1",
			ClientID:   "someclientid",
			SecretHash: "somesecrethash",
			UserName:   "someusername",
			Password:   "somepassword",
		},
		{
			UserPoolID: "eu-west-1_someid2",
			// ClientID:   "",
			UserName: "someusername",
			Password: "somepassword",
		},
		{
			UserPoolID: "eu-west-1_someid1",
			ClientID:   "someclientid",
			SecretHash: "somesecrethash",
			// UserName:   "",
			Password: "somepassword",
		},
		{
			UserPoolID: "eu-west-1_someid1",
			ClientID:   "someclientid",
			SecretHash: "somesecrethash",
			UserName:   "someusername",
			// Password:   "",
		},
	}
	for _, tc := range testCasesOk {
		t.Run(fmt.Sprintf("%v", tc.UserPoolID), func(t *testing.T) {
			_, err := NewClient(tc)
			if err == nil {
				t.Fatalf("should return error")
			}
		})
	}
}

func TestAuth(t *testing.T) {
	// load real testing env
	err := godotenv.Load(".env")
	if err != nil {
		t.Skip("Error loading .env file - skipping the test. Provide .env to make real test")
	}

	// create client
	c, err := NewClient(Input{
		UserPoolID: os.Getenv("COGNITO_USER_POOL_ID"),
		ClientID:   os.Getenv("COGNITO_CLIENT_ID"),
		SecretHash: os.Getenv("COGNITO_SECRET_HASH"),
		UserName:   os.Getenv("COGNITO_USERNAME"),
		Password:   os.Getenv("COGNITO_PASSWORD"),
	})
	if err != nil {
		t.Fatal("Error creating client for real test:", err.Error())
	}

	// call Auth
	jwtToken, err := c.Auth()
	if err != nil {
		t.Fatal("Error in auth, please check the error, credentials:", err.Error())
	}

	if jwtToken == "" {
		t.Fatal("No error but jwtToken is empty")
	}

	timeDiff := time.Now().Unix() - c.tokenExpireAt.Unix()
	if timeDiff > 2 {
		t.Fatalf("tokenExpireAt should be fresh but is %d sec older\n", timeDiff)
	}

	prevAccessToken, prevExpire := c.accessToken, c.tokenExpireAt
	err = c.initiateRefreshAuth()
	if err != nil {
		t.Fatal("initiateRefreshAuth should not return error but: ", err.Error())
	}

	if prevExpire.Equal(c.tokenExpireAt) {
		t.Fatal("tokenExpireAt should refresh and not be the same")
	}

	if prevAccessToken == c.accessToken {
		t.Fatal("accessTokens should differ")
	}
}

func TestAuth_fail(t *testing.T) {
	// load real testing env
	err := godotenv.Load(".env")
	if err != nil {
		t.Skip("Error loading .env file - skipping the test. Provide .env to make real test")
	}

	type tc struct {
		name string
		c    *Client
	}

	var testCases []tc

	// create client wrong ClientID
	c, err := NewClient(Input{
		UserPoolID: os.Getenv("COGNITO_USER_POOL_ID"),
		ClientID:   os.Getenv("COGNITO_CLIENT_ID") + "X",
		SecretHash: os.Getenv("COGNITO_SECRET_HASH"),
		UserName:   os.Getenv("COGNITO_USERNAME"),
		Password:   os.Getenv("COGNITO_PASSWORD"),
	})
	if err != nil {
		t.Fatal("Error creating client for real test:", err.Error())
	}
	testCases = append(testCases, tc{name: "wrong ClientID", c: c})

	// create client wrong SecretHash
	c, err = NewClient(Input{
		UserPoolID: os.Getenv("COGNITO_USER_POOL_ID"),
		ClientID:   os.Getenv("COGNITO_CLIENT_ID"),
		SecretHash: os.Getenv("COGNITO_SECRET_HASH") + "X",
		UserName:   os.Getenv("COGNITO_USERNAME"),
		Password:   os.Getenv("COGNITO_PASSWORD"),
	})
	if err != nil {
		t.Fatal("Error creating client for real test:", err.Error())
	}
	testCases = append(testCases, tc{name: "wrong SecretHash", c: c})

	// create client wrong wrong UserName
	c, err = NewClient(Input{
		UserPoolID: os.Getenv("COGNITO_USER_POOL_ID"),
		ClientID:   os.Getenv("COGNITO_CLIENT_ID"),
		SecretHash: os.Getenv("COGNITO_SECRET_HASH"),
		UserName:   os.Getenv("COGNITO_USERNAME") + "X",
		Password:   os.Getenv("COGNITO_PASSWORD"),
	})
	if err != nil {
		t.Fatal("Error creating client for real test:", err.Error())
	}
	testCases = append(testCases, tc{name: "wrong UserName", c: c})

	// create client wrong Password
	c, err = NewClient(Input{
		UserPoolID: os.Getenv("COGNITO_USER_POOL_ID"),
		ClientID:   os.Getenv("COGNITO_CLIENT_ID"),
		SecretHash: os.Getenv("COGNITO_SECRET_HASH"),
		UserName:   os.Getenv("COGNITO_USERNAME"),
		Password:   os.Getenv("COGNITO_PASSWORD") + "X",
	})
	if err != nil {
		t.Fatal("Error creating client for real test:", err.Error())
	}
	testCases = append(testCases, tc{name: "wrong Password", c: c})

	for _, tc := range testCases {
		t.Run(fmt.Sprintf("%v", tc.name), func(t *testing.T) {
			_, err := tc.c.Auth()
			if err == nil {
				t.Fatalf("should return error")
			}
		})
	}
}
