package handlers

import (
	"context"
	"fmt"
	"net/http"

	"github.com/dylandreimerink/windesheim-security/db"
	"github.com/gorilla/sessions"
)

func getSessionFromContext(ctx context.Context) *sessions.Session {
	if sessionInt := ctx.Value("session"); sessionInt != nil {
		if session, ok := sessionInt.(*sessions.Session); ok {
			return session
		}
	}

	return nil
}

func getUserFromSession(session *sessions.Session) *db.User {
	if userInt := session.Values["user"]; userInt != nil {
		if user, ok := userInt.(*db.User); ok {
			return user
		}
	}
	return nil
}

func getAbsoluteLink(req *http.Request, relativePath string) string {
	//Get the current schema
	schema := "http"
	if req.TLS != nil {
		schema += "s"
	}

	//Redirect to landing page on successfull login
	return fmt.Sprintf("%s://%s%s", schema, req.Host, relativePath)
}
