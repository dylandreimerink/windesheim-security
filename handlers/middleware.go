package handlers

import (
	"bytes"
	"context"
	"net/http"
	"runtime/debug"
	"time"

	"github.com/jinzhu/gorm"

	"github.com/dylandreimerink/windesheim-security/db"
	"github.com/gorilla/sessions"
	"github.com/sirupsen/logrus"
)

func init() {

}

func securityHeadersMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		w.Header().Set("X-Frame-Options", "DENY")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("Cache-Control", "no-store, no-cache, must-revalidate")
		w.Header().Set("Pragma", "no-cache")
		next.ServeHTTP(w, req)
	})
}

//accessLogMiddleware will log all http requests as a access log
func accessLogMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		logFields := logrus.Fields{
			"method":      req.Method,
			"url":         req.URL,
			"remote-addr": req.RemoteAddr,
			"user-agent":  req.UserAgent(),
		}

		//Create a spy with which we can see what was sent back to the client
		spy := &httpResponseSpy{Writer: w, ResponseCode: 200}

		//Start a timer
		timeBefore := time.Now()

		next.ServeHTTP(spy, req)

		//Get the time the request took
		logFields["elasped-time"] = time.Since(timeBefore)

		logFields["bytes-sent"] = spy.BytesSent
		logFields["reponse-code"] = spy.ResponseCode

		logrus.WithFields(logFields).Info("Access log")
	})
}

type httpResponseSpy struct {
	Writer       http.ResponseWriter
	BytesSent    int
	ResponseCode int
}

func (spy *httpResponseSpy) Header() http.Header {
	return spy.Writer.Header()
}

func (spy *httpResponseSpy) Write(bytes []byte) (int, error) {
	count, err := spy.Writer.Write(bytes)
	spy.BytesSent += count
	return count, err
}

func (spy *httpResponseSpy) WriteHeader(statusCode int) {
	spy.Writer.WriteHeader(statusCode)
	spy.ResponseCode = statusCode
}

//The session middleware checks if the client has a session, if so adds it to the request context
func sessionMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {

		store := GetSessionStore()

		//Get the session from the store
		session, err := store.Get(req, "winnote")
		if err != nil {
			http.Error(w, "Internal server error", http.StatusInternalServerError)
			logrus.WithError(err).Error("Error while getting session")
			return
		}

		//Create a new context with the session
		newCtx := context.WithValue(req.Context(), "session", session)

		//Overwrite the context
		req = req.WithContext(newCtx)

		//Execute the next middleware or handler
		next.ServeHTTP(w, req)

		//If there is still a session value in the context
		if sessionInt := req.Context().Value("session"); sessionInt != nil {

			//If the value is a *sessions.Session type
			if session, ok := sessionInt.(*sessions.Session); ok {

				//Save the session
				if err := store.Save(req, w, session); err != nil {

					//If we got a error from saving the session
					logrus.WithError(err).Error("Error while saving session")
				}
			}
		}
	})
}

//The late header setter buffers the response body and header and adds them to the response in the correct order
//Normally middleware can't edit headers after content has been written to the body
//Doing this will decrease performace but allow middleware to modify headers after the main handler
func lateHeaderSetterMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		newWriter := &httpLateHeaderSetterResponseWriter{
			Writer:     w,
			BodyBuffer: bytes.Buffer{},
		}

		next.ServeHTTP(newWriter, req)

		_, err := newWriter.BodyBuffer.WriteTo(w)
		if err != nil {
			panic(err)
		}
	})
}

type httpLateHeaderSetterResponseWriter struct {
	HeaderWritten bool
	Writer        http.ResponseWriter
	BodyBuffer    bytes.Buffer
}

func (lhs *httpLateHeaderSetterResponseWriter) Header() http.Header {
	return lhs.Writer.Header()
}

func (lhs *httpLateHeaderSetterResponseWriter) Write(bytes []byte) (int, error) {
	return lhs.BodyBuffer.Write(bytes)
}

func (lhs *httpLateHeaderSetterResponseWriter) WriteHeader(statusCode int) {
	lhs.Writer.WriteHeader(statusCode)
	if lhs.HeaderWritten {
		debug.PrintStack()
	}
	lhs.HeaderWritten = true
}

//The security middleware checks if the request was made by a authenticated client
//If not, a 401 will be returned and a location header pointing to the login page
func authenticationMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		session := getSessionFromContext(req.Context())

		schema := "http"
		if req.TLS != nil {
			schema += "s"
		}

		sessionUser := getUserFromSession(session)
		if sessionUser == nil {
			htmlRedirect(w, req, "/login", "Unauthorized", http.StatusUnauthorized)
			return
		}

		//If not authenticated
		if !sessionUser.Authenticated {
			//Remove user from session
			delete(session.Values, "user")

			htmlRedirect(w, req, "/login", "Unauthorized", http.StatusUnauthorized)
			return
		}

		conn, err := db.GetConnection()
		if err != nil {
			logrus.WithError(err).Error("Error while getting connection")
			htmlRedirect(w, req, "/login", "Unauthorized", http.StatusUnauthorized)
			return
		}

		var dbUser db.User
		if err := conn.First(&dbUser, "id = ?", sessionUser.ID).Error; err != nil {
			if err == gorm.ErrRecordNotFound {
				logrus.WithError(err).Error("Error while getting user from db")
			}

			//Remove user from session
			delete(session.Values, "user")

			htmlRedirect(w, req, "/login", "Unauthorized", http.StatusUnauthorized)
			return
		}

		//If the user has been archived, invalidate the session and redirect to the login page
		if dbUser.Archived {
			//Remove user from session
			delete(session.Values, "user")

			htmlRedirect(w, req, "/login", "Unauthorized", http.StatusUnauthorized)
			return
		}

		//If the password hash or 2fa token has been changed between the start of the session and now.
		//We must invalidate the session
		if !bytes.Equal(dbUser.PasswordHash, sessionUser.PasswordHash) || dbUser.TOTPSecret.String != dbUser.TOTPSecret.String {
			//Remove user from session
			delete(session.Values, "user")

			htmlRedirect(w, req, "/login", "Unauthorized", http.StatusUnauthorized)
			return
		}

		next.ServeHTTP(w, req)
	})
}
