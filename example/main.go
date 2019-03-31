package main

import (
	"encoding/json"
	"fmt"
	"log"
	"os"

	"github.com/dacz/cognitoclientgo"
	"github.com/joho/godotenv"
)

func printAndExit(err error) {
	fmt.Printf("message: %s\ntype: %T\nvalue: %#v\n", err.Error(), err, err)
	os.Exit(1)
}

func main() {
	err := godotenv.Load()
	if err != nil {
		log.Fatal("Error loading .env file")
	}
	c, err := cognitoclientgo.NewClient(cognitoclientgo.Input{
		UserPoolID: os.Getenv("COGNITO_USER_POOL_ID"),
		ClientID:   os.Getenv("COGNITO_CLIENT_ID"),
		SecretHash: os.Getenv("COGNITO_SECRET_HASH"),
		UserName:   os.Getenv("COGNITO_USERNAME"),
		Password:   os.Getenv("COGNITO_PASSWORD"),
	})
	if err != nil {
		printAndExit(err)
	}

	jwtToken, err := c.Auth()
	if err != nil {
		fmt.Println("SHOULD BE HERE")
		printAndExit(err)
	}

	fmt.Printf("Token to use as JWT token is:\n%s\n", jwtToken)

	user, err := c.GetUser()
	if err != nil {
		printAndExit(err)
	}

	upretty, err := json.MarshalIndent(user, "", "    ")
	if err != nil {
		fmt.Printf("User data:\n%#v\n", *user)
	} else {
		fmt.Println(string(upretty))
	}

	fmt.Printf("%#v\n", c.Tokens())

	// should go from cache next time
	// user, err = c.GetUser()
	// if err != nil {
	// 	printAndExit(err)
	// }

	// should force to obtain fresh user data from Cognito no matter the cache
	// user, err = c.GetUser(true)
	// if err != nil {
	// 	printAndExit(err)
	// }
}
