package handlers

import (
	"bytes"
	"context"
	"fmt"
	"net/http"
	"time"

	"github.com/gorilla/sessions"
	"github.com/sirupsen/logrus"
)

func init() {

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
		session, err := store.Get(req, "winappoint")
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
	Writer     http.ResponseWriter
	BodyBuffer bytes.Buffer
}

func (lhs *httpLateHeaderSetterResponseWriter) Header() http.Header {
	return lhs.Writer.Header()
}

func (lhs *httpLateHeaderSetterResponseWriter) Write(bytes []byte) (int, error) {
	return lhs.BodyBuffer.Write(bytes)
}

func (lhs *httpLateHeaderSetterResponseWriter) WriteHeader(statusCode int) {
	lhs.Writer.WriteHeader(statusCode)
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

		loginLink := fmt.Sprintf("%s://%s%s", schema, req.Host, "/login")

		user := getUserFromSession(session)
		if user == nil {
			//Write JS redirect
			fmt.Fprintf(w, "<script>window.location='%s'</script>", loginLink)

			//Redirect to the login page
			http.Redirect(w, req, loginLink, http.StatusUnauthorized)
			return
		}

		next.ServeHTTP(w, req)
	})
}
