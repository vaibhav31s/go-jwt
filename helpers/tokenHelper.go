package helpers

import (
	"context"
	"fmt"
	jwt "github.com/golang-jwt/jwt/v5"
	"go.mongodb.org/mongo-driver/v2/bson"
	"go.mongodb.org/mongo-driver/v2/mongo"
	"go.mongodb.org/mongo-driver/v2/mongo/options"
	"golang-jwt-project/database"
	"log"
	"os"
	"time"
)

type SignedDetails struct {
	Email      string
	First_name string
	Last_name  string
	Uid        string
	User_type  string
	jwt.RegisteredClaims
}

var userCollection *mongo.Collection = database.OpenCollection(database.Client, "user")

var SECRET_KEY = []byte(os.Getenv("SECRET_KEY"))

func GenerateAllTokens(email string, firstname string, lastname string, userType string, uid string) (SignedToken string, SignedRefreshToken string, err error) {
	claims := SignedDetails{
		Email:      email,
		First_name: firstname,
		Last_name:  lastname,
		Uid:        uid,
		User_type:  userType,
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(time.Now().Local().Add(time.Hour * time.Duration(24))),
		},
	}

	refreshClaims := &SignedDetails{
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(time.Now().Local().Add(time.Hour * time.Duration(124))),
		},
	}

	token, err := jwt.NewWithClaims(jwt.SigningMethodHS256, claims).SignedString(SECRET_KEY)
	refreshToken, err := jwt.NewWithClaims(jwt.SigningMethodHS256, refreshClaims).SignedString(SECRET_KEY)
	if err != nil {
		log.Panic(err)
		return
	}
	return token, refreshToken, err
}

func ValidateToken(signedToken string) (claims *SignedDetails, msg string) {
	token, err := jwt.ParseWithClaims(signedToken, &SignedDetails{}, func(token *jwt.Token) (interface{}, error) {
		return SECRET_KEY, nil
	},
	)
	if err != nil {
		msg = err.Error()
	}
	claims, ok := token.Claims.(*SignedDetails)

	if !ok {
		msg = fmt.Sprintf("the token is invalid!")
		msg = err.Error()
		return
	}

	if claims.ExpiresAt == nil || claims.ExpiresAt.Before(time.Now()) {
		msg = fmt.Sprintf("the token is expired!!")
		msg = err.Error()
		return
	}

	return claims, msg
}

func UpdateAllTokens(signedToken string, signedRefreshToken string, userId string) {
	var ctx, cancel = context.WithTimeout(context.Background(), 100*time.Second)
	var updateObj bson.D

	updateObj = append(updateObj, bson.E{"token", signedToken})
	updateObj = append(updateObj, bson.E{"refresh_token", signedRefreshToken})

	Updated_at, _ := time.Parse(time.RFC3339, time.Now().Format(time.RFC3339))
	updateObj = append(updateObj, bson.E{"updated_at", Updated_at})

	upsert := true
	filter := bson.M{"user_id": userId}
	opt := options.UpdateOne().SetUpsert(upsert)
	_, err := userCollection.UpdateOne(
		ctx,
		filter,
		bson.D{{"$set", updateObj}},
		opt,
	)
	defer cancel()

	if err != nil {
		log.Panic(err)
		return
	}
	return
}
