package main

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"log"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/cuotos/glastoscraper"
	"github.com/meehow/securebytes"
	"github.com/zmb3/spotify/v2"
	spotifyauth "github.com/zmb3/spotify/v2/auth"
	"golang.org/x/exp/slices"
	"golang.org/x/oauth2"
)

var (
	version = "unset"
	commit  = "unset"

	ctx  = context.Background()
	auth *spotifyauth.Authenticator
	sb   = securebytes.New([]byte(mustGetEnvVar("COOKIE_SECRET")), securebytes.JSONSerializer{})
)

func mustGetEnvVar(v string) string {
	found := os.Getenv(v)
	if found != "" {
		return found
	}

	log.Fatalf("missing required env var %s", v)
	return ""
}

func main() {

	log.SetFlags(log.Lshortfile)
	if err := run(); err != nil {
		log.Fatal(err)
	}
}

func run() error {
	hostname := mustGetEnvVar("HOSTNAME")
	auth = spotifyauth.New(
		spotifyauth.WithClientID(mustGetEnvVar("SPOTIFY_CLIENT_ID")),
		spotifyauth.WithClientSecret(mustGetEnvVar("SPOTIFY_CLIENT_SECRET")),
		spotifyauth.WithRedirectURL(fmt.Sprintf("%s/oauth2/callback", hostname)),
		spotifyauth.WithScopes(
			spotifyauth.ScopeUserLibraryRead,
		),
	)
	mux := http.DefaultServeMux

	mux.HandleFunc("/versionz", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(fmt.Sprintf("%s-%s", version, commit)))
	})
	mux.HandleFunc("/oauth2/callback", completeAuthHandler)
	mux.HandleFunc("/oauth2/login", loginAuthHandler)
	mux.HandleFunc("/oauth2/clear", func(w http.ResponseWriter, r *http.Request) {
		clearCookie(w, r, "session_token")
		http.Redirect(w, r, "/", http.StatusTemporaryRedirect)
	})
	mux.HandleFunc("/find", findArtistsHandler)
	mux.HandleFunc("/", indexHandler)

	return http.ListenAndServe(":8080", mux)
}

func indexHandler(w http.ResponseWriter, r *http.Request) {
	w.Write([]byte(`
		<html>
			<body>
				<span>because this is running in dev mode, I need to whitelist Emails linked with Spotify before it will work, let me know your email before clicking login</span><br>
				<ul>
					<li><a href="/oauth2/login">login</a></li>
					<li><a href="/oauth2/clear">clear session cookie</a></li>
					<li><a href="/find">Find Artists (click once)</a></li>
				</ul>
			</body>
		</html>
	`))
}

func findArtistsHandler(w http.ResponseWriter, r *http.Request) {
	c, err := r.Cookie("session_token")
	if err != nil {
		if err == http.ErrNoCookie {
			http.Redirect(w, r, "/", http.StatusTemporaryRedirect)
			return
		}
		// TODO: handle cookie found, but err
	}

	token := &oauth2.Token{}
	err = sb.DecryptBase64(c.Value, token)
	if err != nil {
		http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
		log.Println(err)
		return
	}

	client := spotify.New(auth.Client(ctx, token))

	user, err := client.CurrentUser(ctx)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		log.Println(err)
	}
	log.Println(user.DisplayName, r.URL.String())

	fmt.Printf("getting spotify artists for %s\n", user.DisplayName)
	spotifyLikedArtists, err := getSpotifyLikedArtist(client)
	if err != nil {
		fmt.Println(err)
	}

	glastoScraper, _ := glastoscraper.New(2023)
	glastoArtists, _ := glastoScraper.GetAllArtists()

	matchedArtists := []string{}

	for _, likedArtist := range spotifyLikedArtists {
		for _, glastoArtist := range glastoArtists {
			if strings.EqualFold(likedArtist, glastoArtist) {
				log.Printf("%s found %s\n", user.DisplayName, likedArtist)
				matchedArtists = append(matchedArtists, likedArtist)
			}
		}
	}

	slices.Sort(matchedArtists)
	output := ""
	for _, a := range matchedArtists {
		output += fmt.Sprintf("%s\n", a)
	}
	w.Write([]byte(output))
}

func getSpotifyLikedArtist(c *spotify.Client) ([]string, error) {

	uniqueLikedArtistsMap := make(map[string]any)

	likedTracks, err := c.CurrentUsersTracks(ctx, spotify.Limit(50))
	if err != nil {
		log.Println(err)
	}

	for page := 1; ; page++ {

		log.Printf("getting page %d", page)

		for _, t := range likedTracks.Tracks {
			uniqueLikedArtistsMap[t.Artists[0].Name] = struct{}{}
		}

		err := c.NextPage(ctx, likedTracks)
		if err == spotify.ErrNoMorePages {
			break
		}
		if err != nil {
			log.Println(err)
		}
	}

	uniqueArtists := make([]string, len(uniqueLikedArtistsMap))

	i := 0
	for a := range uniqueLikedArtistsMap {
		uniqueArtists[i] = a
		i++
	}

	return uniqueArtists, nil
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
	oauthState, err := r.Cookie("oauthstate")
	if err != nil {
		http.Error(w, "Couldn't get token", http.StatusNotFound)
		return
	}
	token, err := auth.Token(r.Context(), oauthState.Value, r)
	if err != nil {
		http.Error(w, "failed to parse token", http.StatusInternalServerError)
		fmt.Println(err)
		return
	}

	if st := r.FormValue("state"); st != oauthState.Value {
		http.NotFound(w, r)
		log.Fatalf("state mismatch: %s != %s\n", st, oauthState.Value)
	}

	fmt.Printf("%+v", token)

	b64, err := sb.EncryptToBase64(token)
	if err != nil {
		log.Println(err)
	}

	tokenCookie := http.Cookie{
		Name:  "session_token",
		Value: b64,
		Path:  "/",
	}

	http.SetCookie(w, &tokenCookie)

	w.Write([]byte(`
		<html><body>
		<span>login successful<span><br>
		<a href="/">home</a></body></home>
	`))
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
