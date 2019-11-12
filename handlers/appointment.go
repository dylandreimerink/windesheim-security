package handlers

import (
	"encoding/json"
	"net/http"
	"time"

	"github.com/dylandreimerink/windesheim-security/db"
	"github.com/sirupsen/logrus"
)

func init() {
	SecureRouter.HandleFunc("/appointment/overview", handlerAppointmentOverview)
	SecureRouter.HandleFunc("/appointment/new", handlerNewAppointment)
	SecureRouter.HandleFunc("/appointment/feed", handlerAppointmentFeed)
}

func handlerAppointmentOverview(w http.ResponseWriter, req *http.Request) {

	session := getSessionFromContext(req.Context())

	viewData := map[string]interface{}{
		"Error": "",
	}

	render := func() {
		renderTemplate(w, "full-site.gohtml", "appointment-overview.gohtml", TemplateData{
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

	var ownAppointments []db.Appointment
	if err := conn.Where("end_time > ? and owner_id = ?", time.Now(), user.ID).Find(&ownAppointments).Error; err != nil {
		viewData["Error"] = "Internal server error, please try again later"
		logrus.WithError(err).Error("Error while querying database for appointments")
		w.WriteHeader(500)
		render()
		return
	}

	viewData["appointments"] = ownAppointments

	render()
}

func handlerAppointmentFeed(w http.ResponseWriter, req *http.Request) {
	session := getSessionFromContext(req.Context())

	var appointments []db.Appointment

	render := func() {
		w.Header().Set("Content-Type", "application/json")
		encoder := json.NewEncoder(w)
		encoder.Encode(appointments)
	}

	user := getUserFromSession(session)
	if user == nil {
		w.WriteHeader(401)
		return
	}

	start, err := time.Parse(time.RFC3339, req.URL.Query().Get("start"))
	if err != nil {
		http.Error(w, "Missing or invalid start param", 400)
		return
	}

	end, err := time.Parse(time.RFC3339, req.URL.Query().Get("end"))
	if err != nil {
		http.Error(w, "Missing or invalid end param", 400)
		return
	}

	conn, err := db.GetConnection()
	if err != nil {
		logrus.WithError(err).Error("Error while getting database connection")
		w.WriteHeader(500)
		render()
		return
	}

	if err := conn.Where("start_time >= ? and end_time <= ? and owner_id = ?", start, end, user.ID).Find(&appointments).Error; err != nil {
		logrus.WithError(err).Error("Error while querying database for appointments")
		w.WriteHeader(500)
		render()
		return
	}

	render()
}

func handlerNewAppointment(w http.ResponseWriter, req *http.Request) {
	formValues := map[string]string{}
	formErrors := map[string]string{}

	viewData := map[string]interface{}{
		"Error":      "",
		"FormValues": formValues,
		"FormErrors": formErrors,
	}

	render := func() {
		renderTemplate(w, "full-site.gohtml", "appointment-form.gohtml", TemplateData{
			Request:  req,
			ViewData: viewData,
		})
	}

	session := getSessionFromContext(req.Context())
	user := getUserFromSession(session)
	if user == nil {
		w.WriteHeader(401)
		return
	}

	if req.Method == http.MethodPost {

		err := req.ParseForm()
		if err != nil {
			viewData["Error"] = "Error while processing input"
			logrus.WithError(err).Error("Error while parsing form body")
			render()
			return
		}

		viewData["FormValues"] = map[string]string{
			"Title":       req.Form.Get("Title"),
			"Description": req.Form.Get("Description"),
			"StartTime":   req.Form.Get("StartTime"),
			"EndTime":     req.Form.Get("EndTime"),
			"Location":    req.Form.Get("Location"),
		}

		if len(req.Form.Get("Title")) == 0 {
			viewData["Error"] = "Missing required fields"
			formErrors["Title"] = "Title is a required field"
			render()
			return
		}

		if len(req.Form.Get("StartTime")) == 0 {
			viewData["Error"] = "Missing required fields"
			formErrors["StartTime"] = "Start time is a required field"
			render()
			return
		}

		if len(req.Form.Get("EndTime")) == 0 {
			viewData["Error"] = "Missing required fields"
			formErrors["EndTime"] = "End time is a required field"
			render()
			return
		}

		startTime, err := time.Parse("02-01-2006 15:04:05", req.Form.Get("StartTime"))
		if err != nil {
			viewData["Error"] = "Incorrect input"
			formErrors["StartTime"] = "Incorrect start time, should be in format: dd-mm-yy ss:mm:hh"
			render()
			return
		}

		endTime, err := time.Parse("02-01-2006 15:04:05", req.Form.Get("EndTime"))
		if err != nil {
			viewData["Error"] = "Incorrect input"
			formErrors["EndTime"] = "Incorrect end time, should be in format: dd-mm-yy ss:mm:hh got: " + req.Form.Get("EndTime")
			render()
			return
		}

		newAppointment := db.Appointment{
			Title:       req.Form.Get("Title"),
			Description: req.Form.Get("Description"),
			StartTime:   startTime,
			EndTime:     endTime,
			Owner:       *user,
		}

		conn, err := db.GetConnection()
		if err != nil {
			viewData["Error"] = "Internal server error, please try again later"
			logrus.WithError(err).Error("Error while getting database connection")
			render()
			return
		}

		if err := conn.Save(&newAppointment).Error; err != nil {
			viewData["Error"] = "Internal server error, please try again later"
			logrus.WithError(err).Error("Error while saving new appointment")
			render()
			return
		}

		http.Redirect(w, req, getAbsoluteLink(req, "/appointment/overview"), http.StatusSeeOther)
		return
	} else if req.Method == http.MethodGet {
		query := req.URL.Query()

		format := time.RFC3339
		if query.Get("allDay") == "true" {
			format = "2006-01-02"
		}

		if start, err := time.Parse(format, query.Get("start")); err == nil {
			formValues["StartTime"] = start.Format("02-01-2006 15:04:05")
		}

		if end, err := time.Parse(format, query.Get("end")); err == nil {
			formValues["EndTime"] = end.Format("02-01-2006 15:04:05")
		}
	}

	render()
}
