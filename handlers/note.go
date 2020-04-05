package handlers

import (
	"fmt"
	"net/http"
	"strconv"

	"github.com/jinzhu/gorm"

	"github.com/dylandreimerink/windesheim-security/db"
	"github.com/gorilla/mux"
	"github.com/sirupsen/logrus"
)

func init() {
	SecureRouter.HandleFunc("/note/overview", handlerNotesOverview)
	SecureRouter.HandleFunc("/note", handlerEditNote)
	SecureRouter.HandleFunc("/note/", handlerEditNote)
	SecureRouter.HandleFunc("/note/{id:[0-9]+}", handlerEditNote)
	SecureRouter.Methods("POST").Path("/note/{id:[0-9]+}/delete").HandlerFunc(handlerDeleteNote)
}

func handlerNotesOverview(w http.ResponseWriter, req *http.Request) {

	session := getSessionFromContext(req.Context())

	viewData := map[string]interface{}{
		"Error": "",
	}

	render := func() {
		renderTemplate(w, "full-site.gohtml", "note-overview.gohtml", TemplateData{
			Request:  req,
			ViewData: viewData,
		})
	}

	user := getUserFromSession(session)
	if user == nil {
		w.WriteHeader(401)
		return
	}

	conn, err := db.GetConnection()
	if err != nil {
		viewData["Error"] = "Internal server error, please try again later"
		logrus.WithError(err).Error("Error while getting database connection")
		w.WriteHeader(500)
		render()
		return
	}

	var notes []db.Note
	if err := conn.Where("owner_id = ?", user.ID).Find(&notes).Error; err != nil {
		viewData["Error"] = "Internal server error, please try again later"
		logrus.WithError(err).Error("Error while querying database for notes")
		w.WriteHeader(500)
		render()
		return
	}

	viewData["Notes"] = notes

	session.Values["csrfToken"], err = generateCSRFToken()
	if err != nil {
		logrus.WithError(err).Error("Error while generating CSRF token")
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	viewData["CSRFToken"] = session.Values["csrfToken"]

	render()
}

func handlerEditNote(w http.ResponseWriter, req *http.Request) {
	session := getSessionFromContext(req.Context())

	viewData := map[string]interface{}{
		"Error": "",
	}

	render := func() {
		var err error
		session.Values["csrfToken"], err = generateCSRFToken()
		if err != nil {
			logrus.WithError(err).Error("Error while generating CSRF token")
			w.WriteHeader(http.StatusInternalServerError)
			return
		}

		viewData["CSRFToken"] = session.Values["csrfToken"]

		renderTemplate(w, "full-site.gohtml", "note-edit.gohtml", TemplateData{
			Request:  req,
			ViewData: viewData,
		})
	}

	user := getUserFromSession(session)
	if user == nil {
		w.WriteHeader(401)
		return
	}

	conn, err := db.GetConnection()
	if err != nil {
		viewData["Error"] = "Internal server error, please try again later"
		logrus.WithError(err).Error("Error while getting database connection")
		w.WriteHeader(500)
		render()
		return
	}

	id := -1

	pathVars := mux.Vars(req)
	idString, found := pathVars["id"]
	if found {
		id, err = strconv.Atoi(idString)
		if err != nil {
			htmlRedirect(w, req, "/note/overview", "Not found", 404)
			return
		}
	}

	//We set it severalty so we can check in the template if the id is 0 or unspecified
	viewData["NoteID"] = id

	var note db.Note

	if id > -1 {
		if err := conn.First(&note, "id = ? and owner_id = ?", id, user.ID).Error; err != nil && err != gorm.ErrRecordNotFound {
			logrus.WithError(err).Error("Error while getting note from database")
			w.WriteHeader(http.StatusInternalServerError)

			viewData["Error"] = "Internal server error"

			render()
			return
		} else if err == gorm.ErrRecordNotFound {
			htmlRedirect(w, req, "/note/overview", "Not found", 404)
			return
		}
	}

	if req.Method == http.MethodPost {

		if err := req.ParseForm(); err != nil {
			logrus.WithError(err).Error("Error while parsing form")
			w.WriteHeader(http.StatusInternalServerError)

			viewData["Error"] = "Internal server error"

			render()
			return
		}

		token := req.PostForm.Get("csrf-token")
		if token != session.Values["csrfToken"].(string) {
			viewData["Error"] = "Invalid CSRF token, please try again"

			render()
			return
		}

		note.Title = req.PostForm.Get("Title")
		note.Value = req.PostForm.Get("NoteValue")

		if id == -1 {
			note.Owner = *user
		}

		if err := conn.Save(&note).Error; err != nil {
			logrus.WithError(err).Error("Error while inserting/updating note")
			w.WriteHeader(http.StatusInternalServerError)

			viewData["Error"] = "Internal server error"

			render()
			return
		}

		schema := "http"
		if req.TLS != nil {
			schema += "s"
		}

		http.Redirect(w, req, fmt.Sprintf("%s://%s//note/overview", schema, req.Host), http.StatusSeeOther)
		return
	}

	viewData["Note"] = note

	render()
}

func handlerDeleteNote(w http.ResponseWriter, req *http.Request) {
	session := getSessionFromContext(req.Context())

	user := getUserFromSession(session)
	if user == nil {
		w.WriteHeader(401)
		return
	}

	var id int
	var err error

	pathVars := mux.Vars(req)
	idString, found := pathVars["id"]
	if found {
		id, err = strconv.Atoi(idString)
		if err != nil {
			htmlRedirect(w, req, "/note/overview", "Not found", 404)
			return
		}
	}

	if err := req.ParseForm(); err != nil {
		logrus.WithError(err).Error("Error while parsing form")

		htmlRedirect(w, req, "/note/overview", "Error while parsing form", http.StatusBadRequest)
		return
	}

	token := req.PostForm.Get("csrf-token")
	if token != session.Values["csrfToken"].(string) {
		htmlRedirect(w, req, "/note/overview", "Invalid csrf token", http.StatusBadRequest)
		return
	}

	conn, err := db.GetConnection()
	if err != nil {
		logrus.WithError(err).Error("Error while getting database connection")
		htmlRedirect(w, req, "/note/overview", "Internal server error", 500)
		return
	}

	var note db.Note

	if err := conn.First(&note, "id = ? and owner_id = ?", id, user.ID).Error; err != nil && err != gorm.ErrRecordNotFound {
		logrus.WithError(err).Error("Error while getting note from database")
		htmlRedirect(w, req, "/note/overview", "Internal server error", 500)
		return
	} else if err == gorm.ErrRecordNotFound {
		htmlRedirect(w, req, "/note/overview", "Not found", 404)
		return
	}

	if err := conn.Delete(&note).Error; err != nil {
		logrus.WithError(err).Error("Error while deleting note from database")
		htmlRedirect(w, req, "/note/overview", "Internal server error", 500)
		return
	}

	schema := "http"
	if req.TLS != nil {
		schema += "s"
	}

	http.Redirect(w, req, fmt.Sprintf("%s://%s//note/overview", schema, req.Host), http.StatusSeeOther)
	return
}
