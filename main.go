package main

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"log"
	"net/http"
	"net/url"
	"os"

	"github.com/coreos/go-oidc"
	"github.com/joho/godotenv"
	"golang.org/x/oauth2"
)

var (
	oauth2Config *oauth2.Config
	codeVerifier string
)

func main() {
	// Load environment variables from .env file
	err := godotenv.Load()
	if err != nil {
		log.Fatal("Error loading .env file")
	}

	// Get configuration variables from environment
	clientID := os.Getenv("AUTH0_CLIENT_ID")
	domain := os.Getenv("AUTH0_DOMAIN")
	redirectURL := os.Getenv("AUTH0_REDIRECT_URL")

	// Create an OIDC provider
	provider, err := oidc.NewProvider(context.Background(), "https://"+domain+"/")
	if err != nil {
		log.Fatal(err)
	}

	// Configure the OAuth2 client
	oauth2Config = &oauth2.Config{
		ClientID:    clientID,
		Endpoint:    provider.Endpoint(),
		RedirectURL: redirectURL,
		Scopes:      []string{"openid", "profile", "email", "offline_access"},
	}

	// Generate a random state value
	state, _ := generateRandomString(6)

	// Generate code verifier and code challenge
	codeVerifier, err = generateRandomString(64)
	if err != nil {
		log.Fatal("Error generating code verifier:", err)
	}

	codeChallenge, err := generateCodeChallenge(codeVerifier)
	if err != nil {
		log.Fatal("Error generating code challenge:", err)
	}

	// Create the authorization URL with PKCE parameters
	authURL := oauth2Config.AuthCodeURL(state, oauth2.SetAuthURLParam("code_challenge", codeChallenge), oauth2.SetAuthURLParam("code_challenge_method", "S256"))

	// Print the authorization URL for the user to visit
	fmt.Println("Please visit the following URL to authenticate:")
	fmt.Println(authURL)

	// Split callbackURL to get port and path
	u, err := url.Parse(redirectURL)
	if err != nil {
		log.Fatal("Error parsing callback URL:", err)
	}
	port := u.Port()
	path := u.Path

	// Start the HTTP server to handle the callback
	http.HandleFunc(path, callbackHandler)
	log.Fatal(http.ListenAndServe(fmt.Sprintf(":%s", port), nil))
}

func callbackHandler(w http.ResponseWriter, r *http.Request) {
	// Parse the query parameters from the callback URL
	err := r.ParseForm()
	if err != nil {
		http.Error(w, "Failed to parse form", http.StatusInternalServerError)
		return
	}

	// Get the authorization code from the query parameters
	authCode := r.FormValue("code")
	if authCode == "" {
		http.Error(w, "Authorization code not found", http.StatusBadRequest)
		return
	}

	// Exchange the authorization code for tokens
	token, err := oauth2Config.Exchange(r.Context(), authCode, oauth2.SetAuthURLParam("code_verifier", codeVerifier))
	if err != nil {
		http.Error(w, "Failed to exchange authorization code for tokens", http.StatusInternalServerError)
		return
	}

	// Extract the ID token
	idToken, ok := token.Extra("id_token").(string)
	if !ok {
		http.Error(w, "No ID token received", http.StatusInternalServerError)
		return
	}

	// Extract the access token
	accessToken := token.AccessToken

	// Print the tokens
	fmt.Fprintln(w, "Authentication successful!")
	fmt.Fprintln(w, "ID Token:", idToken)
	fmt.Fprintln(w, "Access Token:", accessToken)
	fmt.Fprintln(w, "Refresh Token:", token.RefreshToken)

	fmt.Println("Authentication successful!")
	fmt.Println("ID Token:", idToken)
	fmt.Println("Access Token:", accessToken)
	fmt.Println("Refresh Token:", token.RefreshToken)
}

func generateRandomString(length int) (string, error) {
	const charset = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-._~"
	b := make([]byte, length)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	for i := range b {
		b[i] = charset[int(b[i])%len(charset)]
	}
	return string(b), nil
}

func generateCodeChallenge(codeVerifier string) (string, error) {
	hasher := sha256.New()
	if _, err := hasher.Write([]byte(codeVerifier)); err != nil {
		return "", err
	}
	hash := hasher.Sum(nil)
	return base64.RawURLEncoding.EncodeToString(hash), nil
}
