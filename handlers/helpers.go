package handlers

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"net/http"

	"gopkg.in/go-playground/validator.v9"

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

func htmlRedirect(w http.ResponseWriter, req *http.Request, relativePath string, text string, code int) {
	renderTemplate(w, "simple.gohtml", "redirect.gohtml", TemplateData{
		Request: req,
		ViewData: map[string]interface{}{
			"Path": relativePath,
			"Text": text,
		},
	})

	w.WriteHeader(code)
}

func generateCSRFToken() (string, error) {

	const randSize = 32

	randVal := make([]byte, randSize)

	if _, err := rand.Read(randVal); err != nil {
		return "", err
	}

	return base64.StdEncoding.EncodeToString(randVal), nil
}

func strongPasswordValidationFunc(fl validator.FieldLevel) bool {
	value := fl.Field().String()

	if len(value) < 8 {
		return false
	}

	specialChar := false
	number := false
	upper := false
	lower := false
	for _, char := range value {

		if (char >= '!' && char <= '/') ||
			(char >= ':' && char <= '@') ||
			(char >= '[' && char <= '`') ||
			(char >= '{' && char <= '~') {
			specialChar = true
		}

		if char >= 'a' && char <= 'z' {
			lower = true
		}

		if char >= 'A' && char <= 'Z' {
			upper = true
		}

		if char >= '0' && char <= '9' {
			number = true
		}
	}

	return specialChar && number && upper && lower
}
