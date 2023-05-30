package main

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"time"

	"github.com/zmb3/spotify/v2"
	spotifyauth "github.com/zmb3/spotify/v2/auth"
	"golang.org/x/oauth2"
)

const (
	redirectURI = "http://localhost:3000/oauth2/callback"
)

var (
	ctx  = context.Background()
	auth = spotifyauth.New(
		spotifyauth.WithRedirectURL(redirectURI),
		spotifyauth.WithScopes(
			spotifyauth.ScopePlaylistReadPrivate,
			spotifyauth.ScopeUserReadEmail,
		),
	)
)

func main() {
	log.SetFlags(log.Lshortfile)
	if err := run(); err != nil {
		log.Fatal(err)
	}
}

func run() error {
	mux := http.DefaultServeMux

	mux.HandleFunc("/oauth2/callback", completeAuthHandler)
	mux.HandleFunc("/oauth2/login", loginAuthHandler)
	mux.HandleFunc("/oauth2/clear", func(w http.ResponseWriter, r *http.Request) {
		clearCookie(w, r, "session_token")
		http.Redirect(w, r, "/", http.StatusTemporaryRedirect)
	})
	mux.HandleFunc("/", indexHandler)

	return http.ListenAndServe("127.0.0.1:3000", mux)
}

func indexHandler(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/" {
		http.NotFound(w, r)
		return
	}
	c, err := r.Cookie("session_token")
	if err != nil {
		if err == http.ErrNoCookie {
			w.WriteHeader(http.StatusUnauthorized)
			w.Write([]byte(`<html><body><a href="/oauth2/login">login</a></body></html>`))
			return
		}
		// TODO: handle cookie found, but err
	}

	// cookie was present
	decodedCookie, _ := base64.URLEncoding.DecodeString(c.Value)

	token := &oauth2.Token{}
	json.Unmarshal(decodedCookie, token)

	client := spotify.New(auth.Client(ctx, token))

	user, err := client.CurrentUser(ctx)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		log.Println(err)
	}
	log.Println(user.DisplayName, r.URL.String())

	output := ""

	allPlaylists, err := client.CurrentUsersPlaylists(ctx)
	if err != nil {
		log.Println(err)
	}

	for page := 1; ; page++ {

		for _, p := range allPlaylists.Playlists {
			isPublic := "private"
			if p.IsPublic {
				isPublic = "public "
			}
			output += fmt.Sprintf("%s - %s\n", isPublic, p.Name)
		}

		err = client.NextPage(ctx, allPlaylists)
		if err == spotify.ErrNoMorePages {
			break
		}
		if err != nil {
			log.Println(err)
		}
	}
	w.Write([]byte(output))
}

func loginAuthHandler(w http.ResponseWriter, r *http.Request) {
	// clear existing session cookie
	clearCookie(w, r, "session_token")

	// create oauthState cookie
	oauthState := generateStateOauthCookie(w)

	http.Redirect(w, r, auth.AuthURL(oauthState), http.StatusTemporaryRedirect)
}

func generateStateOauthCookie(w http.ResponseWriter) string {
	var expire = time.Now().Add(365 * 24 * time.Hour)
	b := make([]byte, 16)
	rand.Read(b)
	state := base64.URLEncoding.EncodeToString(b)
	cookie := http.Cookie{Name: "oauthstate", Value: state, Expires: expire}
	http.SetCookie(w, &cookie)

	return state
}

func completeAuthHandler(w http.ResponseWriter, r *http.Request) {

	// read state from cookie
	oauthState, _ := r.Cookie("oauthstate")
	token, err := auth.Token(r.Context(), oauthState.Value, r)
	if err != nil {
		http.Error(w, "Couldn't get token", http.StatusNotFound)
		return
	}

	if st := r.FormValue("state"); st != oauthState.Value {
		http.NotFound(w, r)
		log.Fatalf("state mismatch: %s != %s\n", st, oauthState.Value)
	}

	tok, err := json.Marshal(token)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		log.Fatalf("failed to marshal token: %s", err)
	}

	tokenCookie := http.Cookie{
		Name:  "session_token",
		Value: base64.URLEncoding.EncodeToString(tok),
		Path:  "/",
	}

	http.SetCookie(w, &tokenCookie)

	http.Redirect(w, r, "/", http.StatusTemporaryRedirect)
}

func clearCookie(w http.ResponseWriter, r *http.Request, cookieName string) {
	_, err := r.Cookie(cookieName)
	if err != nil {
		if err != http.ErrNoCookie {
			log.Println(err)
		}
	}

	c := http.Cookie{
		Name:    cookieName,
		Value:   "",
		Path:    "/",
		Expires: time.Unix(0, 0),
	}

	http.SetCookie(w, &c)
}
