package handlers

import (
	"github.com/dylandreimerink/windesheim-security/sqlstore"
	"encoding/base64"
	"encoding/gob"
	"net/http"

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

//Router is the mux on which all routes will be registered
var RootRouter = mux.NewRouter()

var Router = RootRouter.PathPrefix("/").Subrouter()

var StaticFileBox = packr.New("Static file box", "../static")

var sessionStore sessions.Store

func init() {
	//Create a subrouter from the main router so we dont use the same middleware as the dynamic routes
	staticSubrouter := RootRouter.PathPrefix("/static").Subrouter()

	//Everything under /static is served by the static file server
	staticSubrouter.PathPrefix("/").Handler(http.FileServer(StaticFileBox))
	
	//Add the accesslog middleware to the static file routes
	staticSubrouter.Use(accessLogMiddleware)

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
		Path:   "/",
		MaxAge: 86400 * 30, //1 month
		//Secure:   true, //Uncomment when in production
		SameSite: http.SameSiteStrictMode,
		HttpOnly: true,
	}

	sessionStore = sqlStore

	return sessionStore
}
