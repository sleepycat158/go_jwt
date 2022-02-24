package main

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"regexp"
	"strings"
	"time"

	"github.com/golang-jwt/jwt"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
	"golang.org/x/crypto/bcrypt"
)

type Response struct {
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
}

func init() {
	variables := loadEnvironmentVariables()

	connectionString = variables["CONNECTION_STRING"]
	secret = []byte(variables["SECRET"])
	client = newMongoClient()
}

var (
	client           *mongo.Client
	connectionString string
	secret           []byte
)

func main() {
	validGuid := regexp.MustCompile(`^([a-f]|\d){8}-([a-f]|\d){4}-([a-f]|\d){4}-([a-f]|\d){4}-([a-f]|\d){12}$`)

	http.HandleFunc("/obtain", func(w http.ResponseWriter, r *http.Request) {
		defer func() {
			if err := recover(); err != nil {
				log.Println(err)
				w.WriteHeader(500)
			}
		}()

		if r.Method != http.MethodPost {
			w.WriteHeader(400)
			return
		}

		err := r.ParseForm()
		guid := r.Form.Get("guid")

		if err != nil || !validGuid.MatchString(guid) {
			w.WriteHeader(400)
			return
		}

		accessToken, refreshToken := createTokens(guid)
		storeRefreshToken(guid, refreshToken)

		writeResponse(w, accessToken, refreshToken)
	})

	http.HandleFunc("/refresh", func(w http.ResponseWriter, r *http.Request) {
		defer func() {
			if err := recover(); err != nil {
				log.Println(err)
				w.WriteHeader(500)
			}
		}()

		// Ensure that token:
		// 1. is not modified
		// 2. is not expired
		// 3. is not blacklisted (TODO)

		tokenString := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
		token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
			if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
				return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
			}

			return secret, nil
		})

		if err != nil {
			w.WriteHeader(400)
			return
		}

		if claims, ok := token.Claims.(jwt.MapClaims); ok && token.Valid {
			if claims.Valid() != nil {
				w.WriteHeader(400)
				return
			}

			guid := claims["sub"].(string)

			accessToken, refreshToken := createTokens(guid)
			storeRefreshToken(guid, refreshToken)

			writeResponse(w, accessToken, refreshToken)
		} else {
			w.WriteHeader(400)
		}
	})

	log.Fatal(http.ListenAndServe("localhost:8080", nil))
}

func writeResponse(w http.ResponseWriter, accessToken, refreshToken string) {
	response := Response{
		AccessToken:  accessToken,
		RefreshToken: refreshToken,
	}

	json, err := json.Marshal(response)
	if err != nil {
		panic(err)
	}

	w.Header().Set("Content-Type", "application/json")
	w.Write(json)
}

func loadEnvironmentVariables() map[string]string {
	file, err := os.Open(".env")
	handleFatalError(err)
	defer file.Close()

	env := make(map[string]string)
	scanner := bufio.NewScanner(file)

	for scanner.Scan() {
		line := scanner.Text()

		i := strings.Index(line, "=")
		key, value := line[:i], line[i+1:]

		env[key] = value
	}
	handleFatalError(scanner.Err())

	return env
}

func newMongoClient() *mongo.Client {
	serverAPIOptions := options.ServerAPI(options.ServerAPIVersion1)
	clientOptions := options.Client().
		ApplyURI(connectionString).
		SetServerAPIOptions(serverAPIOptions)

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	client, err := mongo.Connect(ctx, clientOptions)
	handleFatalError(err)

	return client
}

func createTokens(guid string) (string, string) {
	issuedAt := time.Now()

	expiresAt := issuedAt.Add(10 * time.Minute)
	accessToken, err := createToken(guid, issuedAt.Unix(), expiresAt.Unix())
	if err != nil {
		panic(err)
	}

	expiresAt = issuedAt.Add(30 * time.Minute)
	refreshToken, err := createToken(guid, issuedAt.Unix(), expiresAt.Unix())
	if err != nil {
		panic(err)
	}

	return accessToken, refreshToken
}

func createToken(subject string, issuedAt int64, expiresAt int64) (string, error) {
	claims := &jwt.StandardClaims{
		Subject:   subject,
		IssuedAt:  issuedAt,
		ExpiresAt: expiresAt,
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS512, claims)
	return token.SignedString(secret)
}

func storeRefreshToken(guid, refreshToken string) {
	collection := client.Database("test").Collection("tokens")

	hash, err := bcrypt.GenerateFromPassword([]byte(refreshToken), bcrypt.DefaultCost)
	if err != nil {
		panic(err)
	}

	// If refresh token for user with such guid already exists, invalidate previous token by updating it.
	// May be i should not do this, if i want to give an opportunity to login from different devices.
	// But then i will need to store some device information in token.
	filter := bson.D{{"guid", guid}}
	update := bson.D{{"$set", bson.D{{"hash", hash}}}}
	options := options.Update().SetUpsert(true)

	collection.UpdateOne(context.TODO(), filter, update, options)
}

func handleFatalError(err error) {
	if err != nil {
		log.Fatal(err)
	}
}
