package main

import (
	"crypto/rand"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"github.com/dgrijalva/jwt-go"
	_ "github.com/lib/pq"
	"golang.org/x/crypto/bcrypt"
	"log"
	"net/http"
	"time"
)

const (
	secretKey = "some_secret_key"
)

var (
	db *sql.DB
)

func init() {
	var err error
	db, err = sql.Open("postgres",
		"postgres://postgres:postgres@db:5432/go_test?sslmode=disable")
	if err != nil {
		log.Fatal(err)
	}
}

type TokenPair struct {
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
}

type Claims struct {
	IP string `json:"ip"`
	jwt.StandardClaims
}

func GenerateTokenPair(ip string, userID string) (TokenPair, error) {
	accessToken := jwt.NewWithClaims(jwt.SigningMethodHS512, Claims{
		IP: ip,
		StandardClaims: jwt.StandardClaims{
			Issuer:    "test",
			Subject:   userID,
			ExpiresAt: time.Now().Add(time.Hour * 24).Unix(),
		},
	})

	accessTokenString, err := accessToken.SignedString([]byte(secretKey))
	if err != nil {
		return TokenPair{}, err
	}

	refreshToken, err := generateRefreshToken(userID)
	if err != nil {
		return TokenPair{}, err
	}

	return TokenPair{
		AccessToken:  accessTokenString,
		RefreshToken: refreshToken,
	}, nil
}

func generateRefreshToken(userID string) (string, error) {
	b := make([]byte, 32)
	_, err := rand.Read(b)
	if err != nil {
		return "", err
	}

	refreshToken := base64.StdEncoding.EncodeToString(b)

	hash, err := bcrypt.GenerateFromPassword([]byte(refreshToken), bcrypt.DefaultCost)
	if err != nil {
		return "", err
	}

	_, err = db.Exec("INSERT INTO refresh_tokens (user_id, token_hash) VALUES ($1, $2)", userID, hash)
	if err != nil {
		return "", err
	}

	return refreshToken, nil
}

func RefreshToken(refreshToken string, ip string) (TokenPair, error) {
	tokenHash, err := bcrypt.GenerateFromPassword([]byte(refreshToken), bcrypt.DefaultCost)
	if err != nil {
		return TokenPair{}, err
	}

	var userID string
	err = db.QueryRow("SELECT user_id FROM refresh_tokens WHERE token_hash = $1", tokenHash).Scan(&userID)
	if err != nil {
		return TokenPair{}, err
	}

	if ip != getIPFromToken(refreshToken) {
		log.Println("IP-адрес изменился, выслано предупреждение на почту")
	}

	accessTokenString, err := generateAccessToken(userID, ip)
	if err != nil {
		return TokenPair{}, err
	}

	return TokenPair{
		AccessToken:  accessTokenString,
		RefreshToken: refreshToken,
	}, nil
}

func generateAccessToken(userID string, ip string) (string, error) {
	accessToken := jwt.NewWithClaims(jwt.SigningMethodHS512, Claims{
		IP: ip,
		StandardClaims: jwt.StandardClaims{
			Issuer:    "test",
			Subject:   userID,
			ExpiresAt: time.Now().Add(time.Hour * 24).Unix(),
		},
	})

	return accessToken.SignedString([]byte(secretKey))
}

func getIPFromToken(token string) string {
	claims, err := jwt.ParseWithClaims(token, &Claims{}, func(token *jwt.Token) (interface{}, error) {
		return []byte(secretKey), nil
	})
	if err != nil {
		log.Println(err)
		return ""
	}

	if claims.Valid {
		return claims.Claims.(*Claims).IP
	}

	return ""
}

func main() {
	http.HandleFunc("/token", func(w http.ResponseWriter, r *http.Request) {
		userID := r.FormValue("user_id")
		ip := r.RemoteAddr

		tokenPair, err := GenerateTokenPair(ip, userID)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		err = json.NewEncoder(w).Encode(tokenPair)
		if err != nil {
			log.Println(err)
			return
		}
	})

	http.HandleFunc("/refresh", func(w http.ResponseWriter, r *http.Request) {
		refreshToken := r.FormValue("refresh_token")
		ip := r.RemoteAddr

		tokenPair, err := RefreshToken(refreshToken, ip)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			log.Println(err)
			return
		}

		err = json.NewEncoder(w).Encode(tokenPair)
		if err != nil {
			log.Println(err)
			return
		}
	})

	log.Fatal(http.ListenAndServe(":8080", nil))
}
