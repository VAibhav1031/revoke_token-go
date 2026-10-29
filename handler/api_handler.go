package handler

import (
	"errors"
	"log"
	"net/http"
	"strconv"
	"strings"
	"time"

	"encoding/json"

	"github.com/jackc/pgx/v5"
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

type post struct {
	PostTitle   string `json:"post_title"`
	PostContent string `json:"post_content"`
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
		internal_server_error(w, "Unexpected instance cause internal server error. TRY LATER :) ")
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
		ret_json := response("BAD_REQUEST", 400, "Invalid Password..")
		w.Header().Add("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		w.Write(ret_json)
		return
	}

	ctx := r.Context()
	hashedPassword, err := hashPassword(w, register_json.Password)
	if err != nil {
		log.Printf("Password Hashing Failure...")
		internal_server_error(w, "Unexpected instance causse internal  server error. TRY LATER :)")
	}

	query_text := `INSERT INTO  app.user (username, hashed_password, email)  VALUES ($1 , $2, $3)`
	tag, err := db.dbPool.Exec(ctx, query_text, register_json.Username, hashedPassword, register_json.Email)
	if err != nil || tag.RowsAffected() == 0 {
		sqlState := strings.Split(err.Error(), " ")
		// SQLSTATE 23505 -- it is for the conflicting UNIQUE constraint  in the SQL
		unique_constraint_conflict := sqlState[len(sqlState)-2] + " " + sqlState[len(sqlState)-1]

		if unique_constraint_conflict == "(SQLSTATE 23505)" {
			log.Printf("Insertion Failed : Unique-Key Constraint error")
			ret_json := response("CONFLICT", 409, "User Already Exists")
			w.Header().Add("Content-Type", "application/json")
			w.Write(ret_json)
			return
		}
		log.Printf("Insertion Failed : %v", err)
		internal_server_error(w, "Unexpected instance cause internal server error. TRY LATER :) ")
		return
	}

	log.Printf("User %s Registered Sucessfully..\n", register_json.Username)
	ret_json := response("OK", 201, "created")
	w.Header().Add("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	w.Write(ret_json)
}

func (h *Handler) LoginHandler(w http.ResponseWriter, r *http.Request) {
	var login_json login

	err := json.NewDecoder(r.Body).Decode(&login_json)
	if err != nil {
		log.Printf("JSON Decoder Error: %v", err)
		internal_server_error(w, "Unexpected instance cause internal server error. TRY LATER :) ")
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
	query_st := `SELECT user_id, hashed_password  from app.user where username=$1`
	err = h.db.dbPool.QueryRow(ctx, query_st, login_json.Username).Scan(&user_id, &hashedPassword)
	if err != nil {
		log.Printf("User doesnt exists : %v\n", err)
		ret_json := response("NOT_FOUND", 404, "User Does not exists")
		w.Header().Add("Content-Type", "application/json")
		w.WriteHeader(http.StatusNotFound)
		w.Write(ret_json)
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
	if tokenString == "" {
		internal_server_error(w, "Unexpected instance cause internal server error. TRY LATER :) ")
		return
	}

	log.Printf("User %s login Sucessfully..\n", login_json.Username)
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

	result := jwtAuthCheck(w, r)
	if result.err != nil {
		return // already managed... all logs and all
	}

	ctx := r.Context()

	if !isJWTRevoked(ctx, rdb, result.jti) {

		remaining_time := time.Now().Unix() - int64(result.current_exp_time)
		err := blockThisJWT(ctx, rdb, result.jti, result.tokenString, time.Duration(remaining_time))
		if err != nil {
			internal_server_error(w, "Unexpected instance cause internal server error. TRY LATER :)")
			return
		}

		log.Println("JWT is Revoked...")

		log.Printf("User %d login Sucessfully..\n", result.user_id)
		ret_json := response("OK", 200, "Logout Sucessfully")
		w.Header().Add("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		w.Write(ret_json)
	} else {
		ret_json := response("UNAUTHORIZED_ERROR/TOKEN_REVOKED", 401, "Token has been revoked or logged out")
		w.Header().Add("Content-Type", "application/json")
		w.WriteHeader(http.StatusUnauthorized)
		w.Write(ret_json)
		return
	}
}

// simple two endpoint for the more better outlook even though we can have the logout to verify ,  but yeash ...
// these two endpoint would be like of the social media post ,  one would be HTTP POST request and another would be something else..

func (db *DBPooler) NewPostHandler(w http.ResponseWriter, r *http.Request) {

	// we have to make the one check of the auth , then  is it revoked or not else no problemoo....
	// cause if the thing already  not

	result := jwtAuthCheck(w, r)
	if result.err != nil {
		return // already managed... all logs and all
	}

	ctx := r.Context()
	if isJWTRevoked(ctx, rdb, result.jti) {
		ret_json := response("UNAUTHORIZED_ERROR/TOKEN_REVOKED", 401, "Token has been revoked or logged out")
		w.Header().Add("Content-Type", "application/json")
		w.WriteHeader(http.StatusUnauthorized)
		w.Write(ret_json)
		return
	}

	var post_detail post

	err := json.NewDecoder(r.Body).Decode(&post_detail)
	if err != nil {
		log.Printf("JSON Decoder Error: %v", err)
		internal_server_error(w, "Unexpected instance cause internal server error. TRY LATER :) ")
		return
	}

	if post_detail.PostTitle == "" {
		ret_json := response("BAD_REQUEST", 400, "Post Title is Empty")
		w.Header().Add("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		w.Write(ret_json)
		return
	}

	if post_detail.PostContent == "" {
		ret_json := response("BAD_REQUEST", 400, "Post Content Empty")
		w.Header().Add("Conten-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		w.Write(ret_json)
		return
	}

	query_st := `INSERT INTO app.posts (post_title,post_content) VALUES ($1, $2);`

	tag, err := db.dbPool.Exec(ctx, query_st, post_detail.PostTitle, post_detail.PostContent)
	if err != nil || tag.RowsAffected() == 0 {
		log.Printf("Insertion Failed : %v", err)
		internal_server_error(w, "Unexpected instance cause internal server error. TRY LATER :) ")
		return
	}

	log.Printf("Post Created Sucessfully")
	ret_json := response("OK", 201, "created")
	w.Header().Add("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	w.Write(ret_json)

}

func (db *DBPooler) GetPostsHandler(w http.ResponseWriter, r *http.Request) {

	result := jwtAuthCheck(w, r)
	if result.err != nil {
		return // already managed... all logs and all
	}

	ctx := r.Context()
	if isJWTRevoked(ctx, rdb, result.jti) {
		ret_json := response("UNAUTHORIZED_ERROR/TOKEN_REVOKED", 401, "Token has been revoked or logged out")
		w.Header().Add("Content-Type", "application/json")
		w.WriteHeader(http.StatusUnauthorized)
		w.Write(ret_json)
		return
	}

	// pagination...
	// how pagination works?!!!

	// pagination is the method in which we wrap the result in the groups without
	// overwhelming a request with all result , we put in standard groups of list
	// 'n' size mostly 10 or 15 depends.. ,  and  then to get the next we have the
	// url (hypermedia which can be HATEOAS hypermedia as the engine of application ,
	// Kind of the 6 constraint of REST ) but yhou can have normal in the JSON we usually
	// see the we provide the a hashed or encoded value which represent the stage of the pagination
	// or just normal number i would say ...

	// we need the query filteration stuff,  to ge the the n_cursor , limit,
	// stuff

	var count int
	var last_q_post_id int
	var last_q_created_at string
	var post_data []postsData

	// username := r.PathValue("username")

	n_cursor := r.URL.Query().Get("next_cursor")
	limit_st := r.URL.Query().Get("limit")

	limit, err := strconv.Atoi(limit_st)
	if err != nil {
		log.Printf("Query parameter conversion error: %v\n", err)
		internal_server_error(w, "")

	}

	if n_cursor != "" {
		// n_cursor is not null only when there is still value and all

		var nc nextCursor
		if unSerialCursor, ok := isValidSignature(n_cursor, scrt_key); ok {

			err := json.Unmarshal([]byte(unSerialCursor), &nc)
			if err != nil {
				//internal_Server_error
				log.Printf("JSON Marshalling Error: %v\n", err)
				internal_server_error(w, "")
				return
			}

			query_st := `SELECT post_id , post_title, post_content from app.posts where user_id = $1 and created_at > $3 limit $4;`
			rows, err := db.dbPool.Query(ctx, query_st, result.user_id, nc.Timestamp, limit)
			if err != nil {
				log.Printf("DB Error: %v\n", err)
				internal_server_error(w, "")
				return
			}

			for rows.Next() {
				var resp postsData
				rows.Scan(&resp.PostID, &resp.PostTitle, &resp.PostContent, &resp.CreatedAt)
				post_data = append(post_data, resp)

			}

			log.Println("len if block", len(post_data))

		}
	} else {

		query_st := `SELECT post_id , post_title, post_content from app.posts where user_id = $1  limit $2;`
		rows, err := db.dbPool.Query(ctx, query_st, result.user_id, limit)
		if err != nil {
			log.Printf("DB Error: %v\n", err)
			internal_server_error(w, "")
			return
		}

		for rows.Next() {
			var resp postsData
			rows.Scan(&resp.PostID, &resp.PostTitle, &resp.PostContent, &resp.CreatedAt)
			post_data = append(post_data, resp)

		}

		log.Println("len else block", len(post_data))
	}

	log.Println("len before check block", len(post_data))
	// why this check cause it is very important to know that we are already using the sql limit keyword to get to that much of row
	// if the row is less than that means it has that much only
	if len(post_data) > 0 {
		log.Println("Len of post_data is > 0")
		last_q_created_at = post_data[len(post_data)-1].CreatedAt
		query_st_has_more := `SELECT count(*) from app.posts where user_id= $1 and created_at> $2`

		err = db.dbPool.QueryRow(ctx, query_st_has_more, result.user_id, last_q_created_at).Scan(&count)
		if err != nil {
			if errors.Is(err, pgx.ErrNoRows) {
				log.Println("No rows found!")
				internal_server_error(w, "")
				return
			} else {
				// This handles database syntax errors, connection drops, etc.
				log.Printf("Database error occurred: %s\n", err.Error())
				internal_server_error(w, "")
				return
			}
		}

		last_q_post_id = post_data[len(post_data)-1].PostID

		// we have to check the count  if it is in the valid range thing or not ...
		if count >= limit || (count < limit && count > 0) {
			has_more := true

			var nc nextCursor = nextCursor{Timestamp: last_q_created_at, ID: last_q_post_id}

			next_cursor_template, err := json.Marshal(nc)
			if err != nil {
				log.Printf("JSON Marshalling Error: %v\n", err)
				internal_server_error(w, "")
				return
			}

			next_cursor_hmac_signed := generateHMAC256signedCursor(next_cursor_template, scrt_key)

			// Populating....

			// pagination_partt..
			var pag paginationJson = paginationJson{HasMore: has_more, NextCursor: next_cursor_hmac_signed}

			// whole return json now ..
			var p_data postsReturn = postsReturn{Data: post_data, Pagination: pag}

			pag_ret, err := json.Marshal(p_data)
			if err != nil {
				log.Printf("JSON Marshalling error: %v\n", err)
				internal_server_error(w, "")
				return
			}

			// return the normal ones.....
			w.Header().Add("Content-Type", "application/json")
			w.WriteHeader(http.StatusOK)
			w.Write(pag_ret)
			return
		}
	}

	// means there is no more to server and all shit thing i would say sooo..

	var pag paginationJson = paginationJson{HasMore: false, NextCursor: ""}
	var p_data postsReturn = postsReturn{Data: post_data, Pagination: pag}
	pag_ret, err := json.Marshal(p_data)
	if err != nil {
		log.Printf("JSON Marshalling error: %v\n", err)
		internal_server_error(w, "")
		return
	}

	w.Header().Add("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	w.Write(pag_ret)

}
