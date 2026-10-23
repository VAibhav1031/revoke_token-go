package handler

import (
	"context"
	"log"
	"net/http"
	"time"

	"encoding/json"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/patrickmn/go-cache"
)

type register struct {
	Username string `json:"username"`
	Email    string `json:"email"`
	Password string `json:"password"`
}

type login struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

type Response struct {
	Code       string `json:"code"`
	StatusCode int    `json:"status_code"`
	Message    string `json:"message"`
}

type logout struct {
}

type DBPooler struct {
	dbPool *pgxpool.Pool
}

// new pool populator
func NewPooler(pool *pgxpool.Pool) *DBPooler {
	return &DBPooler{dbPool: pool}
}

type AuthChecker struct {
	store *cache.Cache
}

func AuthBlockInitiliazer() *AuthChecker {
	return &AuthChecker{store: cache.New(10*time.Minute, 30*time.Second)}

}

type Handler struct {
	at *AuthChecker
	db *DBPooler
}

func NewHandler(auth *AuthChecker, pooler *DBPooler) *Handler {
	return &Handler{at: auth, db: pooler}
}

// i need the register struct which is being required for every registration process.
func (db *DBPooler) RegisterHandler(w http.ResponseWriter, r *http.Request) {
	// use the decoder for the thing

	var register_json register

	err := json.NewDecoder(r.Body).Decode(&register_json)
	if err != nil {
		log.Println("JSON Decoder Error")
		internal_server_error(w, "JSON Marshalling..")
		return
	}

	// validations..
	if register_json.Username == "" || len(register_json.Username) < 4 || len(register_json.Username) > 25 {
		log.Println("Invalid Username.. ")
		ret_json := response("BAD_REQUEST", 400, "Invalid Register Details")
		w.Header().Add("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		w.Write(ret_json)
		return
	}

	if register_json.Email == "" {
		log.Println("Invalid Email format..")
		ret_json := response("BAD_REQUEST", 400, "Invalid Register Details")
		w.Header().Add("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		w.Write(ret_json)
		return
	}

	if register_json.Password == "" || len(register_json.Password) < 8 || len(register_json.Password) > 30 {
		log.Println("Invalid Password...")
		ret_json := response("BAD_REQUEST", 400, "Invalid Register Details")
		w.Header().Add("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		w.Write(ret_json)
		return
	}

	ctx := r.Context()
	hashedPassword := hashPassword(w, register_json.Password)
	query_text := `INSERT INTO TABLE user(username, password, email)  VALUES ($1 , $2, $3)`
	tag, err := db.dbPool.Exec(ctx, query_text, register_json.Username, hashedPassword, register_json.Email)

	if err != nil {
		log.Printf("DB Error: %v", err)
		internal_server_error(w, "")
		return
	}

	if tag.Insert() || tag.RowsAffected() == 0 {
		log.Printf("DB Error : %v", err)
		internal_server_error(w, "")
		return
	}
}

func (h *Handler) LoginHandler(w http.ResponseWriter, r *http.Request) {
	var login_json login

	err := json.NewDecoder(r.Body).Decode(&login_json)
	if err != nil {
		log.Println("JSON Decoder Error")
		return
	}

	// format check
	if login_json.Username == "" || len(login_json.Username) < 4 || len(login_json.Username) > 25 {
		log.Println("Invalid Username.. ")
		ret_json := response("BAD_REQUEST", 400, "Invalid Register Details")
		w.Header().Add("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		w.Write(ret_json)
		return
	}
	if login_json.Password == "" || len(login_json.Password) < 8 || len(login_json.Password) > 30 {
		log.Println("Invalid Password...")
		ret_json := response("BAD_REQUEST", 400, "Invalid Register Details")
		w.Header().Add("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		w.Write(ret_json)
		return
	}

	//validation...

	// query the db for the password and validate that with the provided one
	ctx := r.Context()

	var hashedPassword string
	var user_id int
	query_st := `SELECT user_id, hashed_password  from user where username=$1`
	err = h.db.dbPool.QueryRow(ctx, query_st, login_json.Username).Scan(&user_id, &hashedPassword)
	if err != nil {
		log.Printf("DB Error : %v\n", err)
		internal_server_error(w, "")
		return
	}

	if !checkPassword(hashedPassword, login_json.Password) {
		if !h.at.checkFailedAttempts(login_json.Username) {
			ret_json := response("TOO_MANY_REQUEST", 429, "Blocked for too manny invalid Request")
			w.Header().Add("Content-Type", "application/json")
			w.WriteHeader(http.StatusTooManyRequests)
			w.Write(ret_json)
			return
		}

		ret_json := response("UNAUTHORIZED_REQUEST", 401, "Invalid User Credentials")
		w.Header().Add("Content-Type", "application/json")
		w.WriteHeader(http.StatusUnauthorized)
		w.Write(ret_json)
		return
	}

	tokenString := jwtCreation(user_id)
	ret_json := response("TOKEN", 200, tokenString)
	w.Header().Add("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	w.Write(ret_json)

}

func LogoutHandler(w http.ResponseWriter, r *http.Request) {

	//  we use to give the jwt in the API format for the logout , or what we need to have
	// like we should add something like username or email alongside , now the password or something just to makee
	//sure

	// w4e havbe to give onlyh the

	result := jwtAuthCheck(w)
	if result.err != nil {
		return // already managed... all logs and all
	}

	ctx := context.Background()

	if !isJWTRevoked(ctx, rdb, result.jti) {

		remaining_time := time.Now().Unix() - int64(result.current_exp_time)
		err := blockThisJWT(ctx, rdb, result.jti, result.tokenString, time.Duration(remaining_time))
		if err != nil {
			internal_server_error(w, "")
			return
		}
		ret_json := response("OK", 200, "Logout Sucessfully")
		w.Header().Add("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		w.Write(ret_json)
	} else {
		ret_json := response("NO_CONTENT", 204, "There is no content for this JWT")
		w.Header().Add("Content-Type", "application/json")
		w.WriteHeader(http.StatusNoContent)
		w.Write(ret_json)
	}
}
