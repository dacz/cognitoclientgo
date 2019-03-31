package cognitoclientgo

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"net/http"
	"strings"
	"time"

	"github.com/dacz/cognitoclientgo/srp"
)

// Client is the main struct that enables auth
type Client struct {
	url                 string
	timeout             time.Duration
	region              string
	userPoolID          string
	clientID            string
	secretHash          string
	userName            string
	password            string
	httpc               *http.Client
	lastError           error
	accessToken         string
	idToken             string
	refreshToken        string
	tokensTime          time.Time
	user                User
	csrp                *srp.CognitoSRP
	challengeParameters map[string]string
}

// Input describes required parameters to login
type Input struct {
	UserPoolID string `json:"userPoolId"`
	ClientID   string `json:"clientId"`
	SecretHash string `json:"clientSecret"`
	UserName   string `json:"userName"`
	Password   string `json:"password"`
}

// User holds user data from cognito
type User map[string]string

// Auth starts the authorization and when success, returns the JWTToken
func (c *Client) Auth() (string, error) {
	err := c.initiateAuth()
	if err != nil {
		c.lastError = err
		return "", err
	}
	err = c.respondToAuthChallenge()
	if err != nil {
		c.lastError = err
		return "", err
	}

	return c.idToken, nil
}

// JWTToken returns the token that can be sent in Authorization header
// to API Gateway to authorize against the Cognito UserPool
func (c *Client) JWTToken() string {
	return c.idToken
}

// Tokens returns all three tokens
// when they are empty, you probably need to register
func (c *Client) Tokens() map[string]string {
	return map[string]string{
		"AccessToken":  c.accessToken,
		"IdToken":      c.idToken,
		"RefreshToken": c.refreshToken,
	}
}

func flowHeader(name string) (string, string) {
	return "X-Amz-Target", "AWSCognitoIdentityProviderService." + name
}

func contentHeader() (string, string) {
	return "Content-Type", "application/x-amz-json-1.1"
}

// NewClient initializes client to auth
func NewClient(inp Input) (*Client, error) {
	s := strings.Split(inp.UserPoolID, "_")
	if len(s) < 2 {
		return nil, errors.New("UserPoolId is probably wrong, it should start with region")
	}
	switch {
	case inp.ClientID == "":
		return nil, errors.New("ClientID cannot be empty")
	case inp.UserName == "":
		return nil, errors.New("UserName cannot be empty")
	case inp.Password == "":
		return nil, errors.New("Password cannot be empty")
	default:
	}

	// initialize cognito srp
	var secretHash *string
	if inp.SecretHash != "" {
		secretHash = &inp.SecretHash
	}
	csrp, err := srp.NewCognitoSRP(
		inp.UserName,
		inp.Password,
		inp.UserPoolID,
		inp.ClientID,
		secretHash,
	)
	if err != nil {
		return nil, err
	}

	timeout := 5 * time.Second

	return &Client{
		url:        "https://cognito-idp." + s[0] + ".amazonaws.com/",
		timeout:    timeout,
		httpc:      &http.Client{Timeout: timeout},
		csrp:       csrp,
		region:     s[0],
		userPoolID: inp.UserPoolID,
		clientID:   inp.ClientID,
		secretHash: inp.SecretHash,
		userName:   inp.UserName,
		password:   inp.Password,
	}, nil
}

type initiateAuthInput struct {
	AuthFlow       string
	ClientId       string // lintskip
	AuthParameters map[string]string
	// ClientMetadata: {}
}

// initiateAuth is first step of Auth
func (c *Client) initiateAuth() error {
	iaParams := &initiateAuthInput{
		AuthFlow:       "USER_SRP_AUTH",
		ClientId:       c.clientID,
		AuthParameters: c.csrp.GetAuthParams(),
	}

	// serialize and post to initauth
	var out bytes.Buffer
	enc := json.NewEncoder(&out)
	err := enc.Encode(iaParams)
	if err != nil {
		return err
	}

	// prepare request
	req, err := http.NewRequest("POST", c.url, &out)
	if err != nil {
		return err
	}

	// add headers
	req.Header.Add(contentHeader())
	req.Header.Add(flowHeader("InitiateAuth"))

	resp, err := c.httpc.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	// we need to process it twice and TeeReader here seems not to be more effective
	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return err
	}

	err = checkAWSRespError(body)
	if err != nil {
		return err
	}

	// deserialize json data
	var result struct {
		ChallengeName       string
		ChallengeParameters map[string]string
	}

	// unmarshal here
	err = json.Unmarshal(body, &result)
	if err != nil {
		return err
	}

	if result.ChallengeName != "PASSWORD_VERIFIER" {
		fmt.Printf("Should be PASSWORD_VERIFIER but is %q\n", result.ChallengeName)
		return errors.New("No PASSWORD_VERIFIER response")
	}

	c.challengeParameters = result.ChallengeParameters

	return nil
}

// respondToAuthChallenge is second step to Auth
func (c *Client) respondToAuthChallenge() error {
	achParams, err := c.csrp.PasswordVerifierChallenge(c.challengeParameters, time.Now())
	if err != nil {
		return err
	}

	// serialize
	var out bytes.Buffer
	enc := json.NewEncoder(&out)
	err = enc.Encode(achParams)
	if err != nil {
		return err
	}

	// prepare request
	req, err := http.NewRequest("POST", c.url, &out)
	if err != nil {
		return err
	}

	// add headers
	req.Header.Add(contentHeader())
	req.Header.Add(flowHeader("RespondToAuthChallenge"))

	resp, err := c.httpc.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	// we need to process it twice and TeeReader here seems not to be more effective
	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return err
	}

	err = checkAWSRespError(body)
	if err != nil {
		return err
	}

	// deserialize json data
	var result struct {
		AuthenticationResult struct {
			AccessToken  string
			IdToken      string // lintskip
			RefreshToken string
			TokenType    string
		}
		ChallengeParameters map[string]string
	}

	err = json.Unmarshal(body, &result)
	if err != nil {
		return err
	}

	if result.AuthenticationResult.IdToken == "" {
		fmt.Printf("Missing token in response %#v\n", result)
		return errors.New("Missing tokens in response")
	}

	c.accessToken = result.AuthenticationResult.AccessToken
	c.idToken = result.AuthenticationResult.IdToken
	c.refreshToken = result.AuthenticationResult.RefreshToken
	c.tokensTime = time.Now()

	return nil
}

// GetUser asks for Cognito user data
// if send an argument 'true', it will force download data even if they are cached
// (pointer is not used because we don't want allow any modifications)
func (c *Client) GetUser(forcesl ...bool) (*User, error) {
	if c.accessToken == "" {
		return nil, errors.New("Missing access token. Please authorize first")
	}

	// if we already have user data and not forced, return user from cache
	if (c.user != nil && len(forcesl) == 0) || (len(forcesl) > 0 && !forcesl[0]) {
		return &c.user, nil
	}

	uParams := &struct{ AccessToken string }{AccessToken: c.accessToken}

	// serialize
	var out bytes.Buffer
	enc := json.NewEncoder(&out)
	err := enc.Encode(uParams)
	if err != nil {
		return nil, err
	}

	// prepare request
	req, err := http.NewRequest("POST", c.url, &out)
	if err != nil {
		return nil, err
	}

	// add headers
	req.Header.Add(contentHeader())
	req.Header.Add(flowHeader("GetUser"))

	resp, err := c.httpc.Do(req)
	if err != nil {
		c.lastError = err
		return nil, err
	}
	defer resp.Body.Close()

	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	err = checkAWSRespError(body)
	if err != nil {
		c.lastError = err
		return nil, err
	}

	// deserialize json data
	var result struct {
		UserAttributes []struct {
			Name  string
			Value string
		}
		Username string
	}

	err = json.Unmarshal(body, &result)
	if err != nil {
		c.lastError = err
		return nil, err
	}

	if len(result.UserAttributes) == 0 {
		fmt.Printf("No user attributes in response %#v\n", result)
		return nil, errors.New("No user attributes in response")
	}

	u := User{}

	for _, item := range result.UserAttributes {
		u[item.Name] = item.Value
	}
	u["username"] = result.Username

	c.user = u

	return &c.user, nil
}

// ResourceNotFoundException
// UserNotFoundException
// {\"__type\":\"NotAuthorizedException\",\"message\":\"Incorrect username or password.\"}
func checkAWSRespError(body []byte) error {
	var result map[string]interface{}

	err := json.Unmarshal(body, &result)
	if err != nil {
		return err
	}

	if result["__type"] != nil {
		strE, ok := result["__type"].(string)
		if !ok {
			strE = "UnknownException"
		}
		strM, ok := result["message"].(string)
		if !ok {
			strM = "Unknown message"
		}
		return errors.New("[" + strE + "]: " + strM)
	}
	return nil
}
