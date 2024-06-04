package main

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"net/url"
	"os"
	"time"

	"github.com/coreos/go-oidc"
	"github.com/joho/godotenv"
	"golang.org/x/oauth2"
)

type DeviceCodeResponse struct {
	DeviceCode      string `json:"device_code"`
	UserCode        string `json:"user_code"`
	VerificationURI string `json:"verification_uri_complete"`
	ExpiresIn       int    `json:"expires_in"`
	Interval        int    `json:"interval"`
}

type TokenResponse struct {
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
	IDToken      string `json:"id_token"`
	TokenType    string `json:"token_type"`
	ExpiresIn    int    `json:"expires_in"`
}

func main() {
	// Load environment variables from .env file
	err := godotenv.Load()
	if err != nil {
		log.Fatal("Error loading .env file")
	}

	// Get configuration variables from environment
	clientID := os.Getenv("AUTH0_CLIENT_ID")
	domain := os.Getenv("AUTH0_DOMAIN")
	audience := os.Getenv("AUTH0_AUDIENCE")
	redirectURL := os.Getenv("AUTH0_REDIRECT_URL")

	tokenData, err := loadTokenFromFile("token.json")
	if err != nil {
		log.Println("token file not found")
	}

	if os.Args[1] == "show" {
		if err != nil {
			return
		}
		// Check if local JSON file exists and has valid, non-expired id_token
		if time.Now().Before(tokenData.Expiry) {
			fmt.Println("ID Token:", tokenData.IDToken)
		} else {
			fmt.Println("Expired")
		}
		return
	}

	if os.Args[1] == "refresh" {
		// Create an OIDC provider
		provider, err := oidc.NewProvider(context.Background(), "https://"+domain+"/")
		if err != nil {
			log.Fatal(err)
		}
		// Configure the OAuth2 client
		oauth2Config := &oauth2.Config{
			ClientID:    clientID,
			Endpoint:    provider.Endpoint(),
			RedirectURL: redirectURL,
			Scopes:      []string{"openid", "profile", "email", "offline_access"},
		}
		tokenData, err := refreshToken(oauth2Config, tokenData.RefreshToken)
		if err != nil {
			log.Fatal("Failed to refresh token")
			return
		}
		saveTokenToFile(tokenData, "token.json")
		fmt.Println("ID Token:", tokenData.IDToken)
		return
	}

	// Device Authorization Request
	deviceCodeURL := fmt.Sprintf("https://%s/oauth/device/code", domain)
	data := url.Values{}
	data.Set("client_id", clientID)
	data.Set("scope", "openid email profile offline_access")
	data.Set("audience", audience)

	resp, err := http.PostForm(deviceCodeURL, data)
	if err != nil {
		log.Fatal("Error making device code request:", err)
	}
	defer resp.Body.Close()

	var deviceCodeResponse DeviceCodeResponse
	err = json.NewDecoder(resp.Body).Decode(&deviceCodeResponse)
	if err != nil {
		log.Fatal("Error decoding device code response:", err)
	}

	// Print the verification URL for the user to visit
	fmt.Println("Please visit the following URL to authenticate:")
	fmt.Println(deviceCodeResponse.VerificationURI)

	// Poll for token
	tokenURL := fmt.Sprintf("https://%s/oauth/token", domain)
	interval := time.Duration(deviceCodeResponse.Interval) * time.Second

	for {
		time.Sleep(interval)

		data := url.Values{}
		data.Set("grant_type", "urn:ietf:params:oauth:grant-type:device_code")
		data.Set("device_code", deviceCodeResponse.DeviceCode)
		data.Set("client_id", clientID)

		resp, err := http.PostForm(tokenURL, data)
		if err != nil {
			log.Fatal("Error making token request:", err)
		}
		defer resp.Body.Close()

		if resp.StatusCode == http.StatusOK {
			var tokenResponse TokenResponse
			err = json.NewDecoder(resp.Body).Decode(&tokenResponse)
			if err != nil {
				log.Fatal("Error decoding token response:", err)
			}

			// Print the tokens
			fmt.Println("Access Token:", tokenResponse.AccessToken)
			fmt.Println("Refresh Token:", tokenResponse.RefreshToken)
			fmt.Println("ID Token:", tokenResponse.IDToken)

			// Save the token data to a local JSON file
			tokenData := TokenData{
				AccessToken:  tokenResponse.AccessToken,
				RefreshToken: tokenResponse.RefreshToken,
				IDToken:      tokenResponse.IDToken,
				// TODO: store expiry
			}
			saveTokenToFile(tokenData, "token.json")
			break
		} else {
			var errorResponse struct {
				Error string `json:"error"`
			}
			err = json.NewDecoder(resp.Body).Decode(&errorResponse)
			if err != nil {
				log.Fatal("Error decoding error response:", err)
			}

			if errorResponse.Error == "authorization_pending" {
				fmt.Println("Authorization pending. Waiting for user to authenticate...")
			} else if errorResponse.Error == "slow_down" {
				interval += time.Second
				fmt.Printf("Polling too fast. Increasing interval to %s...\n", interval)
			} else {
				log.Fatalf("Unexpected error: %s\n", errorResponse.Error)
			}
		}
	}
}

type TokenData struct {
	AccessToken  string    `json:"access_token"`
	RefreshToken string    `json:"refresh_token"`
	IDToken      string    `json:"id_token"`
	Expiry       time.Time `json:"expiry"`
}

func saveTokenToFile(tokenData TokenData, filename string) error {
	data, err := json.Marshal(tokenData)
	if err != nil {
		return err
	}
	return os.WriteFile(filename, data, 0644)
}

func loadTokenFromFile(filename string) (TokenData, error) {
	data, err := os.ReadFile(filename)
	if err != nil {
		return TokenData{}, err
	}
	var tokenData TokenData
	err = json.Unmarshal(data, &tokenData)
	return tokenData, err
}

func refreshToken(config *oauth2.Config, refreshToken string) (TokenData, error) {
	token := &oauth2.Token{
		RefreshToken: refreshToken,
	}

	tokenSource := config.TokenSource(context.Background(), token)
	newToken, err := tokenSource.Token()
	if err != nil {
		return TokenData{}, err
	}

	tokenData := TokenData{
		AccessToken:  newToken.AccessToken,
		RefreshToken: newToken.RefreshToken,
		IDToken:      newToken.Extra("id_token").(string),
		Expiry:       newToken.Expiry,
	}

	return tokenData, nil
}
