package main

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"time"

	"github.com/coreos/go-oidc"
	"github.com/joho/godotenv"
	"golang.org/x/oauth2"
)

var (
	oauth2Config *oauth2.Config
)

type TokenData struct {
	AccessToken  string    `json:"access_token"`
	RefreshToken string    `json:"refresh_token"`
	IDToken      string    `json:"id_token"`
	Expiry       time.Time `json:"expiry"`
}

func main() {
	// Load environment variables from .env file
	err := godotenv.Load()
	if err != nil {
		log.Fatal("Error loading .env file")
	}

	// Get configuration variables from environment
	clientID := os.Getenv("AUTH0_CLIENT_ID")
	clientSecret := os.Getenv("AUTH0_CLIENT_SECRET")
	domain := os.Getenv("AUTH0_DOMAIN")
	redirectURL := os.Getenv("AUTH0_REDIRECT_URL")

	// Create an OIDC provider
	provider, err := oidc.NewProvider(context.Background(), "https://"+domain+"/")
	if err != nil {
		log.Fatal(err)
	}

	// Configure the OAuth2 client
	oauth2Config = &oauth2.Config{
		ClientID:     clientID,
		ClientSecret: clientSecret,
		Endpoint:     provider.Endpoint(),
		RedirectURL:  redirectURL,
		Scopes:       []string{"openid", "profile", "email", "offline_access"},
	}

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
		tokenData, err := refreshToken(oauth2Config, tokenData.RefreshToken)
		if err != nil {
			log.Fatal("Failed to refresh token")
			return
		}
		saveTokenToFile(tokenData, "token.json")
		fmt.Println("ID Token:", tokenData.IDToken)
		return
	}
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
