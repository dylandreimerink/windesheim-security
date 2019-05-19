package handlers

import (
	"html/template"
	"net/http"
	"strings"

	"github.com/dylandreimerink/windesheim-security/db"

	"github.com/davecgh/go-spew/spew"
	"github.com/gobuffalo/packd"
	packr "github.com/gobuffalo/packr/v2"
	"github.com/pkg/errors"
	"github.com/sirupsen/logrus"
	"github.com/spf13/viper"
)

const TemplateHotParseConfigKey = "template.hot_parse"

//TemplateBox is a packr box containing all templates
var TemplateBox = packr.New("Template Box", "../templates")

var templates map[string]*template.Template
var views map[string]*template.Template

var mainTpl = `{{ define "main" }} {{ template "base" . }} {{ end }}`

var templateFuncs = template.FuncMap{
	"dump":    spew.Sdump,
	"getUser": templateFuncGetUser,
}

func init() {
	viper.SetDefault(TemplateHotParseConfigKey, false)
}

func loadTemplates() error {

	//Reset the templates var
	templates = make(map[string]*template.Template)

	//Reset the views var
	views = make(map[string]*template.Template)

	//Parse the main template
	mainTemplate := template.New("main")
	mainTemplate, err := mainTemplate.Parse(mainTpl)
	if err != nil {
		return err
	}

	mainTemplate.Funcs(templateFuncs)

	//Walk over every helper and parse it as well
	err = TemplateBox.WalkPrefix("helpers/", func(filename string, file packd.File) error {
		var err error
		mainTemplate, err = mainTemplate.Parse(file.String())
		if err != nil {
			return err
		}
		return nil
	})
	if err != nil {
		return err
	}

	//Walk over every layout and parse it as well
	err = TemplateBox.WalkPrefix("layouts/", func(filename string, file packd.File) error {
		//Clone the main template
		layoutTemplate, err := mainTemplate.Clone()
		if err != nil {
			return err
		}

		layoutTemplate, err = layoutTemplate.Parse(file.String())
		if err != nil {
			return err
		}

		//Trim the views map and add it to the template list
		templates[strings.TrimPrefix(filename, "layouts/")] = layoutTemplate
		return nil
	})
	if err != nil {
		return err
	}

	//Walk over every view
	err = TemplateBox.WalkPrefix("views/", func(filename string, file packd.File) error {
		//Parse the view
		viewTemplate, err := template.New(filename).Parse(file.String())
		if err != nil {
			return err
		}

		//Trim the views map and add it to the template list
		views[strings.TrimPrefix(filename, "views/")] = viewTemplate

		return nil
	})
	if err != nil {
		return err
	}

	return nil
}

type TemplateData struct {
	//The request object
	Request *http.Request
	//Data related to rendering the current view
	ViewData map[string]interface{}
}

func renderTemplate(w http.ResponseWriter, templateName string, viewName string, data TemplateData) {
	if templates == nil || viper.GetBool(TemplateHotParseConfigKey) {
		err := loadTemplates()
		if err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			logrus.WithField("template", templateName).Error(errors.WithMessage(err, "Error while loading template"))
			return
		}
	}

	tmpl, ok := templates[templateName]
	if !ok {
		w.WriteHeader(http.StatusInternalServerError)
		logrus.WithField("template", templateName).Error("Template doesn't exist")
		return
	}

	view, ok := views[viewName]
	if !ok {
		w.WriteHeader(http.StatusInternalServerError)
		logrus.WithField("view", viewName).Error("View doesn't exist")
		return
	}

	viewTmpl, err := tmpl.Clone()
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		logrus.WithField("template", templateName).Error(errors.WithMessage(err, "Error while cloning template"))
		return
	}

	for _, t := range view.Templates() {
		viewTmpl.AddParseTree(t.Name(), t.Tree)
	}

	w.Header().Set("Content-Type", "text/html; charset=utf-8")

	err = viewTmpl.Execute(w, data)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		logrus.WithFields(logrus.Fields{
			"template": templateName,
			"data":     data,
		}).WithError(err).Error("Error while rendering template")
	}
}

//templateFuncGetUser returns the current user or nil if no user is logged in
func templateFuncGetUser(req *http.Request) *db.User {
	session := getSessionFromContext(req.Context())
	return getUserFromSession(session)
}
