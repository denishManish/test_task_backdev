package main

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"log"
	"net/http"
	"net/smtp"
	"os"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/gofrs/uuid"
	"github.com/golang-jwt/jwt/v5"
	"github.com/jackc/pgx/v5"
	"golang.org/x/crypto/bcrypt"
)

var signingKey = loadingSigningKey()
var conn = connectDB()

type User struct {
	GUID  uuid.UUID
	Email string
}

type RefreshToken struct {
	GUID         uuid.UUID
	RefreshToken string
}

type ResponseBody struct {
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
}

type AccessTokenClaim struct {
	IP string `json:"ip"`
	jwt.RegisteredClaims
}

func main() {
	defer conn.Close(context.Background())

	router := gin.Default()

	router.POST("/tokens", obtainTokens)
	router.POST("/tokens/refresh", refreshTokens)

	router.POST("/mockdata", insertMockdata)
	router.GET("/users", listUsers)
	router.GET("/refresh-tokens", listRefreshTokens)

	router.Run(":8080")
}

func loadingSigningKey() []byte {
	var signingKey = make([]byte, 64)

	file, err := os.Open("SECRET_KEY")
	if err != nil {
		log.Fatal(err)
	}

	n, err := file.Read(signingKey)
	if err != nil {
		log.Fatal(err)
	}
	if n != 64 {
		log.Fatalf("Loaded signing key less than 64 bytes (512 bit): n = %v", n)
	}

	return signingKey
}

func connectDB() *pgx.Conn {
	database_url := "postgres://postgres:postgres@db:5432/postgres"
	conn, err := pgx.Connect(context.Background(), database_url)
	if err != nil {
		log.Fatalf("Unable to connect to database: %v\n", err)
	}

	_, err = conn.Exec(context.Background(), `
		create table if not exists users (
			guid uuid default gen_random_uuid(),
			email varchar not null,
			primary key (guid)
		)
	`)
	if err != nil {
		log.Fatalf("Unable to create table users: %v\n", err)
	}

	_, err = conn.Exec(context.Background(), `
		create table if not exists refresh_tokens (
			user_guid uuid,
			token varchar,
			primary key(user_guid),
			constraint fk_user_guid
			   	foreign key(user_guid)
			   	references users(guid)
				on delete cascade
		)
	`)
	if err != nil {
		log.Fatalf("Unable to create table refresh_tokens: %v\n", err)
	}

	return conn
}

func obtainTokens(c *gin.Context) {
	guid := c.Query("guid")
	var user User
	err := conn.QueryRow(context.Background(), "select guid from users where guid = $1", guid).Scan(&user.GUID)
	if err != nil {
		log.Printf("Unable to find user with provided GUID: %v\n", err)
		c.Status(http.StatusBadRequest)
		return
	}

	ip := c.ClientIP()

	responseBody, refreshTokenHash, err := genTokens(guid, ip)
	if err != nil {
		c.Status(http.StatusInternalServerError)
		return
	}

	_, err = conn.Exec(context.Background(), "insert into refresh_tokens (user_guid, token) values ($1, $2)", guid, refreshTokenHash)
	if err != nil {
		log.Printf("Unable to insert hash of the refresh token to db: %v\n", err)
		c.Status(http.StatusInternalServerError)
		return
	}

	c.IndentedJSON(http.StatusOK, responseBody)
}

func refreshTokens(c *gin.Context) {
	accessTokenStr := c.PostForm("access_token")
	refreshTokenStr := c.PostForm("refresh_token")

	var claims AccessTokenClaim

	accessToken, err := jwt.ParseWithClaims(accessTokenStr, &claims, func(token *jwt.Token) (interface{}, error) {
		return signingKey, nil
	})
	if err != nil {
		log.Printf("Unable to parse access token: %v\n", err)
		c.Status(http.StatusBadRequest)
		return
	}
	if !accessToken.Valid {
		log.Printf("Access token isn't valid: %v\n", err)
		c.Status(http.StatusBadRequest)
		return
	}
	fmt.Printf("GUID: %v\nIP: %v\n", claims.Subject, claims.IP)

	var refreshTokenHashDB string
	err = conn.QueryRow(context.Background(), "select token from refresh_tokens where user_guid = $1", claims.Subject).Scan(&refreshTokenHashDB)
	if err != nil {
		log.Printf("Unable to find refresh token in database: %v\n", err)
		c.Status(http.StatusBadRequest)
		return
	}
	refreshTokenHash := []byte(refreshTokenHashDB)
	refreshToken, err := base64.StdEncoding.DecodeString(refreshTokenStr)
	if err != nil {
		log.Printf("Unable to decode refresh token: %v\n", err)
		c.Status(http.StatusInternalServerError)
		return
	}
	if err = bcrypt.CompareHashAndPassword(refreshTokenHash, refreshToken); err != nil {
		log.Printf("Refresh token isn't equivalent to the one stored in database: %v\n", err)
		c.Status(http.StatusBadRequest)
		return
	}

	if c.ClientIP() != claims.IP {
		log.Println("IP is changed from the one in the refresh roken")

		from := "some_email_address@gmail.com"
		pass := "some_password"
		var to string
		err = conn.QueryRow(context.Background(), "select email from users where guid = &1", claims.Subject).Scan(&to)
		if err != nil {
			log.Printf("Unable to find user in database: %v\n", err)
			c.Status(http.StatusInternalServerError)
			return
		}
		msg := "There was an attempt to update access to the resourse from another IP-address"

		err := smtp.SendMail("smtp.gmail.com:587",
			smtp.PlainAuth("", from, pass, "smtp.gmail.com"),
			from, []string{to}, []byte(msg))
		if err != nil {
			log.Printf("smtp error: %s", err)
			c.Status(http.StatusBadRequest)
		}

		return
	}

	var responseBody ResponseBody
	responseBody, refreshTokenHash, err = genTokens(claims.Subject, claims.IP)
	if err != nil {
		c.Status(http.StatusInternalServerError)
		return
	}
	_, err = conn.Exec(context.Background(), "update refresh_tokens set token = $1 where user_guid = $2", refreshTokenHash, claims.Subject)
	if err != nil {
		log.Printf("Unable to update hash of the refresh token in db: %v\n", err)
		c.Status(http.StatusInternalServerError)
		return
	}

	c.IndentedJSON(http.StatusOK, responseBody)
}

func genTokens(guid string, ip string) (ResponseBody, []byte, error) {
	accessToken := jwt.NewWithClaims(jwt.SigningMethodHS512, AccessTokenClaim{
		ip,
		jwt.RegisteredClaims{
			Subject:  guid,
			IssuedAt: jwt.NewNumericDate(time.Now()),
		},
	})
	accessTokenStr, err := accessToken.SignedString(signingKey)
	if err != nil {
		log.Printf("Unable to sign access token: %v\n", err)
		return ResponseBody{}, nil, err
	}

	refreshToken := make([]byte, 32)
	_, err = rand.Read(refreshToken)
	if err != nil {
		log.Printf("Refresh token wasn't generated: %v\n", err)
		return ResponseBody{}, nil, err
	}
	refreshTokenHash, err := bcrypt.GenerateFromPassword(refreshToken, bcrypt.DefaultCost)
	if err != nil {
		log.Printf("Unable to get bcrypt hash of the refresh token: %v\n", err)
		return ResponseBody{}, nil, err
	}
	refreshTokenStr := base64.StdEncoding.EncodeToString(refreshToken)

	return ResponseBody{accessTokenStr, refreshTokenStr}, refreshTokenHash, nil
}

func insertMockdata(c *gin.Context) {
	rows := [][]any{
		{"clarejenkins@gmail.com"},
		{"janeharrison@gmail.com"},
	}

	copyCount, err := conn.CopyFrom(
		context.Background(),
		pgx.Identifier{"users"},
		[]string{"email"},
		pgx.CopyFromRows(rows),
	)
	if err != nil {
		log.Printf("Unable to copy data to database: %v\n", err)
		c.Status(http.StatusInternalServerError)
		return
	}
	c.JSON(http.StatusOK, map[string]int64{"copied": copyCount})
}

func listUsers(c *gin.Context) {
	var users []User
	var user User
	rows, _ := conn.Query(context.Background(), "select * from users")
	_, err := pgx.ForEachRow(rows, []any{&user.GUID, &user.Email}, func() error {
		users = append(users, user)
		return nil
	})
	if err != nil {
		log.Printf("Unable to list users: %v\n", err)
		c.Status(http.StatusInternalServerError)
		return
	}
	c.IndentedJSON(http.StatusOK, users)
}

func listRefreshTokens(c *gin.Context) {
	var refreshTokens []RefreshToken
	var refreshToken RefreshToken
	rows, _ := conn.Query(context.Background(), "select * from refresh_tokens")
	_, err := pgx.ForEachRow(rows, []any{&refreshToken.GUID, &refreshToken.RefreshToken}, func() error {
		refreshTokens = append(refreshTokens, refreshToken)
		return nil
	})
	if err != nil {
		log.Printf("Unable to list refresh tokens: %v\n", err)
		c.Status(http.StatusInternalServerError)
		return
	}
	c.IndentedJSON(http.StatusOK, refreshTokens)
}
