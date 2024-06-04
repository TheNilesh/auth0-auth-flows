package main

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
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

var (
	oauth2Config *oauth2.Config
	codeVerifier string
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

	// Extract the access token and refresh token
	accessToken := token.AccessToken
	refreshToken := token.RefreshToken

	// Save the token data to a local JSON file
	tokenData := TokenData{
		AccessToken:  accessToken,
		RefreshToken: refreshToken,
		IDToken:      idToken,
		Expiry:       token.Expiry,
	}
	saveTokenToFile(tokenData, "token.json")

	// Print the tokens
	fmt.Fprintln(w, "Authentication successful!")
	fmt.Fprintln(w, "ID Token:", idToken)
	fmt.Fprintln(w, "Access Token:", accessToken)
	fmt.Fprintln(w, "Refresh Token:", refreshToken)

	fmt.Println("Authentication successful!")
	fmt.Println("ID Token:", idToken)
	fmt.Println("Access Token:", accessToken)
	fmt.Println("Refresh Token:", refreshToken)
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
