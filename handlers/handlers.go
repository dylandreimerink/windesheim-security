package handlers

import (
	"encoding/base64"
	"encoding/gob"
	"fmt"
	"net/http"
	"net/url"
	"strings"

	"github.com/dylandreimerink/windesheim-security/sqlstore"

	"github.com/dylandreimerink/windesheim-security/db"
	packr "github.com/gobuffalo/packr/v2"
	"github.com/gorilla/mux"
	"github.com/gorilla/sessions"
	"github.com/sirupsen/logrus"
	"github.com/spf13/viper"
)

const (
	SessionKeyConfigKey = "security.cookie_key"
)

//RootRouter is the mux on which all routes will be registered
var RootRouter = mux.NewRouter()

//Router is the router which is used for insecure dynamic routes
var Router = RootRouter.PathPrefix("/").Subrouter()

//SecureRouter is the router which is used for secure dynamic routes
//Only authenticated users may access routes in this router
var SecureRouter = RootRouter.PathPrefix("/").Subrouter()

var StaticFileBox = packr.New("Static file box", "../static")

var sessionStore sessions.Store

func init() {
	//Create a subrouter from the main router so we dont use the same middleware as the dynamic routes
	staticSubrouter := RootRouter.PathPrefix("/static").Subrouter()

	//Everything under /static is served by the static file server
	staticSubrouter.PathPrefix("/").Handler(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		w.Header().Set("Cache-Control", "public, max-age=604800, immutable")

		req.RequestURI = strings.TrimPrefix(req.RequestURI, "/static/")

		var err error
		req.URL, err = url.Parse(req.RequestURI)
		if err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			fmt.Fprint(w, err.Error())
		}

		http.FileServer(StaticFileBox).ServeHTTP(w, req)
	}))

	//Add the accesslog middleware to the static file routes
	staticSubrouter.Use(accessLogMiddleware)

	//Register late header setter so other middleware can rewrite headers
	Router.Use(lateHeaderSetterMiddleware)
	//Register session middleware so all routes have access to sessions
	Router.Use(sessionMiddleware)
	//Register access log middleware
	Router.Use(accessLogMiddleware)
	//Security header middleware
	Router.Use(securityHeadersMiddleware)

	//Register late header setter so other middleware can rewrite headers
	SecureRouter.Use(lateHeaderSetterMiddleware)
	//Register session middleware so all routes have access to sessions
	SecureRouter.Use(sessionMiddleware)
	//Register authentication middleware
	SecureRouter.Use(authenticationMiddleware)
	//Register access log middleware
	SecureRouter.Use(accessLogMiddleware)
	//Security header middleware
	Router.Use(securityHeadersMiddleware)

	//Register models at gob
	gob.Register(&db.User{})
}

func GetSessionStore() sessions.Store {
	if sessionStore != nil {
		return sessionStore
	}

	cookieKeyBase64 := viper.GetString(SessionKeyConfigKey)
	if cookieKeyBase64 == "" {
		logrus.Error("Missing required config: security.cookie_key")
		return nil
	}

	cookieKey, err := base64.StdEncoding.DecodeString(cookieKeyBase64)
	if err != nil {
		logrus.Error("security.cookie_key must be a base64 string")
		return nil
	}

	conn, err := db.GetConnection()
	if err != nil {
		logrus.Error("Can't get database connection")
		return nil
	}

	sqlStore := sqlstore.New(conn.DB(), cookieKey)
	sqlStore.Options = &sessions.Options{
		Domain:   viper.GetString("http.domainname"),
		Path:     "/",
		MaxAge:   86400 * 30, //1 month
		Secure:   viper.GetBool("http.tls.enabled") && viper.GetBool("http.tls.redirect_http"),
		SameSite: http.SameSiteStrictMode,
		HttpOnly: true,
	}

	sessionStore = sqlStore

	return sessionStore
}
