package handler

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"strings"
	"time"
	"uuid"

	"github.com/golang-jwt/jwt/v5"
	"github.com/patrickmn/go-cache"
	"github.com/redis/go-redis/v9"
	"golang.org/x/crypto/bcrypt"
)

var blockedTime = time.Minute * 15
var maxAttempts = 4

var scrt_key []byte

var rdb *redis.Client

func init() {
	scrt_key = []byte(os.Getenv("SECRET_KEY"))
	if scrt_key == nil {
		log.Println("SECRET_KEY is Not Available....")
	}

	redisPass := os.Getenv("REDIS_PASSWORD")
	// basically we are defining the struct of the NewClient function parameter
	rdb = redis.NewClient(&redis.Options{
		Addr:     "redis:6379",
		Password: redisPass,
		DB:       0,
	})

	_, err := rdb.Ping(context.Background()).Result()
	if err != nil {
		log.Fatalf("Could not connect to the Redis: %v", err)
	}

	log.Println("Connected to Redis...")
}

type authCheckResult struct {
	user_id          int
	jti              string
	tokenString      string
	current_exp_time int64
	err              error
}

func response(code string, status_code int, msg string) []byte {
	re := Response{Code: code, StatusCode: status_code, Message: msg}

	re_by, err := json.Marshal(re)
	if err != nil {
		log.Printf("Marshalling error : %v", err)
		return nil
	}
	return re_by
}

func internal_server_error(w http.ResponseWriter, msg string) {
	ret_json := response("INTERNAL_SERVER_ERROR", 500, msg)
	w.Header().Add("Content-Type", "application/json")
	w.WriteHeader(http.StatusInternalServerError)
	w.Write(ret_json)
}

func hashPassword(w http.ResponseWriter, password string) ([]byte, error) {

	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return nil, err
	}

	return hashedPassword, nil
}

func checkPassword(hashedPassword string, password string) bool {
	err := bcrypt.CompareHashAndPassword([]byte(hashedPassword), []byte(password))

	return err == nil
}

func jwtCreation(user_id int) string {
	claims := jwt.MapClaims{
		"user_id": user_id,
		"exp":     time.Now().Add(time.Minute * 10).Unix(),
		"jti":     uuid.New(),
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)

	tokeString, err := token.SignedString([]byte(scrt_key))

	if err != nil {
		log.Printf("Failed Creation JWT Token: %v", err)
	}

	return tokeString
}

func jwtVerification(tokenString string) (float64, string, float64, bool) {
	token, err := jwt.Parse(tokenString, func(t *jwt.Token) (any, error) {
		if _, ok := t.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("Unexpected Signing MEthod", t.Header["alg"])
		}
		return scrt_key, nil
	})

	if err != nil || !token.Valid {
		log.Printf("Token Expired...", err)
		return -1, "", 0, false
	}

	if claims, ok := token.Claims.(jwt.MapClaims); ok {
		return claims["user_id"].(float64), claims["jti"].(string), claims["exp"].(float64), true
	}

	return -1, "", 0, false
}

func jwtAuthCheck(w http.ResponseWriter, req *http.Request) *authCheckResult {

	bearerToken := req.Header.Get("Authorization")

	if bearerToken == "" || !strings.HasPrefix(bearerToken, "Bearer") {
		log.Printf("Empty Bearerer Token.. %v", bearerToken)
		// call the error  thing
		ret_json := response("INVALID_AUTH_TOKEN", 401, "Token is Empty or invalid")
		w.Header().Add("Content-Type", "application/json")
		w.WriteHeader(http.StatusUnauthorized)
		w.Write(ret_json)
		return &authCheckResult{user_id: -1, jti: "", tokenString: "", current_exp_time: 0, err: fmt.Errorf("Empty Token or Invalid Token..")}
	}

	token := strings.TrimPrefix(bearerToken, "Bearer ")

	user_id, jti, current_exp_time, ok := jwtVerification(token)

	if !ok {
		log.Println("Expired Token....")
		ret_json := response("EXPIRED_AUTH_TOKEN", 401, "Expired Token")
		w.Header().Add("Content-Type", "application/json")
		w.WriteHeader(http.StatusUnauthorized)
		w.Write(ret_json)
		return &authCheckResult{user_id: -1, jti: "", tokenString: "", current_exp_time: 0, err: fmt.Errorf("Expired Token..")}
	}

	return &authCheckResult{user_id: int(user_id), jti: jti, tokenString: token, current_exp_time: int64(current_exp_time), err: nil}
}

func (c *AuthChecker) checkFailedAttempts(userName string) bool {

	err := c.store.Increment(userName, 1)
	if err != nil {
		c.store.Set(userName, 1, cache.DefaultExpiration)
		return false
	}

	attempts, _ := c.store.Get(userName)
	if attempts.(int) >= maxAttempts {
		c.store.Set(userName, 1, blockedTime)
		return true
	}

	return false

}

func (c *AuthChecker) isBlocked(userName string) bool {

	attempts, _ := c.store.Get(userName)
	if attempts.(int) >= maxAttempts {
		return true
	}

	return false
}

func blockThisJWT(ctx context.Context, rd *redis.Client, jti string, jwtToken string, remainingTime time.Duration) error {

	// Add the jti

	err := rdb.Set(ctx, jti, jwtToken, remainingTime).Err()
	if err != nil {
		log.Printf("Error in Redis Set: %v", err)
		return err
	}
	return nil
}

func isJWTRevoked(ctx context.Context, rd *redis.Client, jti string) bool {

	_, err := rd.Get(ctx, jti).Result()

	if err == redis.Nil {
		log.Println("Key does not exists or Expired ")
		return false
	} else if err != nil {
		log.Printf("Error in Redis Get : %v", err)
		return false
	}

	return true
}

func generateHMAC256signedCursor(cursor_det []byte, secretKey []byte) string {
	mac := hmac.New(sha256.New, secretKey)
	mac.Write([]byte(cursor_det))

	// (passing nil means calculate from scratch)
	rawMac := mac.Sum(nil)

	//  raw binary array into a human-readable Hex string
	hexMac := hex.EncodeToString(rawMac)

	return base64.RawStdEncoding.EncodeToString([]byte(cursor_det)) + "." + hexMac

}

func isValidSignature(receivedCursor string, secretKey []byte) ([]byte, bool) {
	result_ := strings.Split(receivedCursor, ".")
	if len(result_) != 2 {
		return nil, false
	}
	payload, digestHMAC := result_[0], result_[1]

	receivedMAC, err := hex.DecodeString(digestHMAC)
	if err != nil {
		log.Printf("Error in DecodingString of receivedMac: %v", err)
		return nil, false
	}

	payloadDecoded, err := base64.RawStdEncoding.DecodeString(payload)
	if err != nil {
		log.Printf("Unable to decode  base64 cursor detail: %v", err)
		return nil, false
	}

	// Calculate expected MAC
	mac := hmac.New(sha256.New, secretKey)
	mac.Write(payloadDecoded)
	expectedMAC := mac.Sum(nil)

	// Verify signature FIRST (Timing-attack safe via hmac.Equal)
	if !hmac.Equal(receivedMAC, expectedMAC) {
		log.Printf("Invalid Cursor..: %v\n", err)
		return nil, false
	}

	return payloadDecoded, true
}
