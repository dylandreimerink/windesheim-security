package handlers

import (
	"image/png"
	"net/http"

	"github.com/dylandreimerink/windesheim-security/db"
	"github.com/sirupsen/logrus"

	"github.com/pquerna/otp/totp"
)

func init() {
	//Register routes
	SecureRouter.HandleFunc("/profile", handlerProfile)
	SecureRouter.Methods("POST").Path("/2fa/totp").HandlerFunc(handlerNewTOTP)
	SecureRouter.Methods("POST").Path("/2fa/totp/verify").HandlerFunc(handlerVerifyNewTOTP)
}

func handlerProfile(w http.ResponseWriter, req *http.Request) {
	renderTemplate(w, "full-site.gohtml", "profile.gohtml", TemplateData{
		Request: req,
	})
}

func handlerNewTOTP(w http.ResponseWriter, req *http.Request) {
	session := getSessionFromContext(req.Context())

	user := getUserFromSession(session)

	key, err := totp.Generate(totp.GenerateOpts{
		Issuer:      "Winappoint",
		AccountName: user.Email,
	})

	if err != nil {
		logrus.WithError(err).Error("Error while generating totp code")
		w.WriteHeader(500)
		return
	}

	// conn, err := db.GetConnection()
	// if err != nil {
	// 	logrus.WithError(err).Error("Error while getting database connection")
	// 	w.WriteHeader(500)
	// 	return
	// }

	session.Values["pending-totp-secret"] = key.Secret()

	// user.TOTPSecret = key.Secret()
	// if conn.Save(user).Error != nil {
	// 	logrus.WithError(err).Error("Error while saving totp secret")
	// 	w.WriteHeader(500)
	// 	return
	// }

	w.Header().Set("Content-Type", "image/png")
	w.Header().Set("Cache-Control", "no-store") //Disable cache, otherwise the browser will store the qr code

	totpImage, err := key.Image(300, 300)
	if err != nil {
		logrus.WithError(err).Error("Error while generating QR image")
		w.WriteHeader(500)
		return
	}

	err = png.Encode(w, totpImage)
	if err != nil {
		logrus.WithError(err).Error("Error while generating png image")
		w.WriteHeader(500)
	}
}

func handlerVerifyNewTOTP(w http.ResponseWriter, req *http.Request) {
	session := getSessionFromContext(req.Context())

	user := getUserFromSession(session)

	code := req.PostFormValue("code")
	if code == "" {
		http.Error(w, "missing field 'code'", http.StatusBadRequest)
		return
	}

	secret, found := session.Values["pending-totp-secret"]
	if !found {
		logrus.Error("Error, missing field 'pending-totp-secret' in session")
		http.Error(w, "Code invalid", http.StatusConflict)
		return
	}

	db, err := db.GetConnection()
	if err != nil {
		logrus.WithError(err).Error("Error while getting connection")
		w.WriteHeader(http.StatusInternalServerError)
	}

	if totp.Validate(code, secret.(string)) {
		user.TwoFactorAuthenticationMode = "totp"
		user.TOTPSecret = secret.(string)
		if err := db.Save(user).Error; err != nil {
			logrus.WithError(err).Error("Error saving user")
			w.WriteHeader(http.StatusInternalServerError)
		}
	} else {
		http.Error(w, "Code invalid", http.StatusConflict)
		return
	}

	//Invalidate the current session
	session.Values["user"] = nil

	w.WriteHeader(http.StatusOK)
}
