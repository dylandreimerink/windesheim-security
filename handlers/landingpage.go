package handlers

import (
	"net/http"
)

func init() {
	//Register the landing page route
	Router.HandleFunc("/", handlerLandingPage)
}

func handlerLandingPage(w http.ResponseWriter, req *http.Request) {
	renderTemplate(w, "landingpage.gohtml", TemplateData{
		Request: req,
	})
}
