package handlers

import (
	"fmt"
	"image/png"
	"net/http"
	"strconv"
	"strings"

	"github.com/go-playground/locales/en"
	ut "github.com/go-playground/universal-translator"
	"github.com/gorilla/mux"
	"github.com/spf13/viper"
	"golang.org/x/crypto/bcrypt"
	"gopkg.in/go-playground/validator.v9"
	en_translations "gopkg.in/go-playground/validator.v9/translations/en"

	"github.com/dylandreimerink/windesheim-security/db"
	"github.com/sirupsen/logrus"

	"github.com/pquerna/otp/totp"
)

func init() {
	//Register routes
	SecureRouter.HandleFunc("/profile", handlerProfile)
	SecureRouter.HandleFunc("/users", handlerUserOverview)
	SecureRouter.HandleFunc("/users/{id:[0-9]+}", handlerEditUser)
	SecureRouter.Methods("POST").Path("/users/delete").HandlerFunc(handlerDeleteUsers)
	SecureRouter.Methods("POST").Path("/users/archive").HandlerFunc(handlerArchiveUsers)
	SecureRouter.Methods("POST").Path("/users/new").HandlerFunc(handlerNewUser)
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
		Issuer:      "Winnote",
		AccountName: user.Email,
	})

	if err != nil {
		logrus.WithError(err).Error("Error while generating totp code")
		w.WriteHeader(500)
		return
	}

	session.Values["pending-totp-secret"] = key.Secret()

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

	logrus.WithFields(logrus.Fields{
		"user-id":     user.ID,
		"remote-addr": req.RemoteAddr,
	}).Info("User requested a new TOTP secret")
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
		return
	}

	if totp.Validate(code, secret.(string)) {
		err = user.TOTPSecret.Scan(secret)
		if err != nil {
			logrus.WithError(err).Error("Error while scanning totp secret")
			w.WriteHeader(http.StatusInternalServerError)
			return
		}

		if err := db.Save(user).Error; err != nil {
			logrus.WithError(err).Error("Error saving user")
			w.WriteHeader(http.StatusInternalServerError)
			return
		}

		logrus.WithFields(logrus.Fields{
			"user-id":     user.ID,
			"remote-addr": req.RemoteAddr,
		}).Info("User configured 2FA")
	} else {
		http.Error(w, "Code invalid", http.StatusConflict)
		return
	}

	//Invalidate the current session
	session.Values["user"] = nil

	w.WriteHeader(http.StatusOK)
}

func handlerUserOverview(w http.ResponseWriter, req *http.Request) {
	session := getSessionFromContext(req.Context())

	user := getUserFromSession(session)

	//Only users with the required permissions may access this page
	if !user.HasPermssion(db.PERMISSION_READ_USER) {
		htmlRedirect(w, req, "/", "Forbidden", http.StatusForbidden)
		return
	}

	conn, err := db.GetConnection()
	if err != nil {
		logrus.WithError(err).Error("Error while getting connection")
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	var users []db.User
	if err := conn.Find(&users).Error; err != nil {
		logrus.WithError(err).Error("Error while getting users from db")
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	session.Values["csrfToken"], err = generateCSRFToken()
	if err != nil {
		logrus.WithError(err).Error("Error while generating CSRF token")
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	renderTemplate(w, "full-site.gohtml", "user-overview.gohtml", TemplateData{
		Request: req,
		ViewData: map[string]interface{}{
			"Users": users,
			"MayEdit": user.HasOneOfPermssions([]db.PermissionKey{
				db.PERMISSION_UPDATE_USER_PASSWORD,
				db.PERMISSION_UPDATE_USER_PASSWORD_RESET,
				db.PERMISSION_UPDATE_USER_TOTP,
			}),
			"MayCreate":  user.HasPermssion(db.PERMISSION_CREATE_USER),
			"MayDelete":  user.HasPermssion(db.PERMISSION_DELETE_USER),
			"MayArchive": user.HasPermssion(db.PERMISSION_ARCHIVE_USER),
			"CSRFToken":  session.Values["csrfToken"],
		},
	})
}

func handlerNewUser(w http.ResponseWriter, req *http.Request) {
	session := getSessionFromContext(req.Context())

	user := getUserFromSession(session)

	//Only users with the required permissions may access this page
	if !user.HasPermssion(db.PERMISSION_CREATE_USER) {
		htmlRedirect(w, req, "/", "Forbidden", http.StatusForbidden)
		return
	}

	if err := req.ParseForm(); err != nil {
		htmlRedirect(w, req, "/users", "Bad request", http.StatusBadRequest)
		return
	}

	//TODO duplicate email check

	//Hash the password using bcrypt (bcrypt also automatically salts the hash)
	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(req.PostForm.Get("Password")), viper.GetInt(NewUserPasswordBcryptCost))
	if err != nil {
		logrus.WithError(err).Error("Error while hashing password for new user")
		htmlRedirect(w, req, "/users", "Error while creating user account", http.StatusBadRequest)
		return
	}

	//Create a new user model
	newUser := &db.User{
		FirstName:    req.PostForm.Get("FirstName"),
		LastName:     req.PostForm.Get("LastName"),
		Email:        req.PostForm.Get("Email"),
		PasswordHash: hashedPassword,

		//Activate since a admin has created the account
		Activated: true,
	}

	conn, err := db.GetConnection()
	if err != nil {
		logrus.WithError(err).Error("Error while creating connection to database")
		htmlRedirect(w, req, "/users", "Error while creating user account", http.StatusBadRequest)
		return
	}

	if err := conn.Save(newUser).Error; err != nil {
		logrus.WithError(err).Error("Error while creating user")
		htmlRedirect(w, req, "/users", "Error while creating user account", http.StatusBadRequest)
		return
	}

	logrus.WithFields(logrus.Fields{
		"user-id":     user.ID,
		"new-user-id": newUser.ID,
		"remote-addr": req.RemoteAddr,
	}).Info("User created new user")

	//Get the current schema
	schema := "http"
	if req.TLS != nil {
		schema += "s"
	}

	//Redirect to the confirm email page
	http.Redirect(w, req, fmt.Sprintf("%s://%s%s", schema, req.Host, "/users"), http.StatusSeeOther)

	return
}

func handlerDeleteUsers(w http.ResponseWriter, req *http.Request) {
	session := getSessionFromContext(req.Context())

	user := getUserFromSession(session)

	//Only users with the required permissions may access this page
	if !user.HasPermssion(db.PERMISSION_DELETE_USER) {
		htmlRedirect(w, req, "/", "Forbidden", http.StatusForbidden)
		return
	}

	if err := req.ParseForm(); err != nil {
		htmlRedirect(w, req, "/users", "Bad request", http.StatusBadRequest)
		return
	}

	token := req.PostForm.Get("csrf-token")
	if token != session.Values["csrfToken"].(string) {
		htmlRedirect(w, req, "/users", "Invalid CSRF token", http.StatusBadRequest)
		return
	}

	conn, err := db.GetConnection()
	if err != nil {
		logrus.WithError(err).Error("Error while getting connection")
		htmlRedirect(w, req, "/users", "Internal server error", http.StatusBadRequest)
		return
	}

	userIds := []int{}

	for key := range req.Form {
		if strings.HasPrefix(key, "user[") {
			key = strings.TrimPrefix(key, "user[")
			key = strings.TrimSuffix(key, "]")

			if id, err := strconv.Atoi(key); err == nil {
				userIds = append(userIds, id)
			}
		}
	}

	logrus.WithFields(logrus.Fields{
		"user-id":      user.ID,
		"del-user-ids": userIds,
		"remote-addr":  req.RemoteAddr,
	}).Info("User deleted other users")

	if err := conn.Delete(&db.User{}, "id IN (?)", userIds).Error; err != nil {
		logrus.WithError(err).Error("Error while deleting users")
		htmlRedirect(w, req, "/users", "Internal server error", http.StatusBadRequest)
		return
	}

	schema := "http"
	if req.TLS != nil {
		schema += "s"
	}

	http.Redirect(w, req, fmt.Sprintf("%s://%s%s", schema, req.Host, "/users"), http.StatusSeeOther)
}

func handlerArchiveUsers(w http.ResponseWriter, req *http.Request) {
	session := getSessionFromContext(req.Context())

	user := getUserFromSession(session)

	//Only users with the required permissions may access this page
	if !user.HasPermssion(db.PERMISSION_ARCHIVE_USER) {
		htmlRedirect(w, req, "/", "Forbidden", http.StatusForbidden)
		return
	}

	if err := req.ParseForm(); err != nil {
		htmlRedirect(w, req, "/users", "Bad request", http.StatusBadRequest)
		return
	}

	token := req.PostForm.Get("csrf-token")
	if token != session.Values["csrfToken"].(string) {
		htmlRedirect(w, req, "/users", "Invalid CSRF token", http.StatusBadRequest)
		return
	}

	conn, err := db.GetConnection()
	if err != nil {
		logrus.WithError(err).Error("Error while getting connection")
		htmlRedirect(w, req, "/users", "Internal server error", http.StatusBadRequest)
		return
	}

	userIds := []int{}

	for key := range req.Form {
		if strings.HasPrefix(key, "user[") {
			key = strings.TrimPrefix(key, "user[")
			key = strings.TrimSuffix(key, "]")

			if id, err := strconv.Atoi(key); err == nil {
				userIds = append(userIds, id)
			}
		}
	}

	logrus.WithFields(logrus.Fields{
		"user-id":          user.ID,
		"archive-user-ids": userIds,
		"remote-addr":      req.RemoteAddr,
	}).Info("User archived other users")

	var users []db.User
	if err := conn.Where("id IN (?)", userIds).Find(&users).Error; err != nil {
		logrus.WithError(err).Error("Error while selecting users")
		htmlRedirect(w, req, "/users", "Internal server error", http.StatusBadRequest)
		return
	}

	for _, archiveUser := range users {
		archiveUser.Archived = !archiveUser.Archived
		if err := conn.Save(&archiveUser).Error; err != nil {
			logrus.WithError(err).Error("Error while archiveing users")
			htmlRedirect(w, req, "/users", "Internal server error", http.StatusBadRequest)
			return
		}
	}

	schema := "http"
	if req.TLS != nil {
		schema += "s"
	}

	http.Redirect(w, req, fmt.Sprintf("%s://%s%s", schema, req.Host, "/users"), http.StatusSeeOther)
}

func handlerEditUser(w http.ResponseWriter, req *http.Request) {
	session := getSessionFromContext(req.Context())

	user := getUserFromSession(session)

	//Only users with the required permissions may access this page
	if !user.HasOneOfPermssions([]db.PermissionKey{
		db.PERMISSION_UPDATE_USER_PASSWORD,
		db.PERMISSION_UPDATE_USER_PASSWORD_RESET,
		db.PERMISSION_UPDATE_USER_TOTP,
	}) {
		htmlRedirect(w, req, "/", "Forbidden", http.StatusForbidden)
		return
	}

	pathVars := mux.Vars(req)
	idString, found := pathVars["id"]
	if !found {
		logrus.Error("Error path var 'id' not set")
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	id, err := strconv.Atoi(idString)
	if err != nil {
		logrus.WithError(err).Error("Error 'id' path var is not an integer")
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	conn, err := db.GetConnection()
	if err != nil {
		logrus.WithError(err).Error("Error while getting connection")
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	var editUser db.User
	if err := conn.Where("id = ?", id).First(&editUser).Error; err != nil {
		logrus.WithError(err).Error("Error while getting user from DB")
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	viewData := map[string]interface{}{
		"Error":             "",
		"FormErrors":        map[string]string{},
		"User":              editUser,
		"MayUpdatePassword": user.HasPermssion(db.PERMISSION_UPDATE_USER_PASSWORD),
		"MayResetPassword":  user.HasPermssion(db.PERMISSION_UPDATE_USER_PASSWORD_RESET),
		"MayResetTOTP":      user.HasPermssion(db.PERMISSION_UPDATE_USER_TOTP),
	}

	render := func() {
		session.Values["csrfToken"], err = generateCSRFToken()
		if err != nil {
			logrus.WithError(err).Error("Error while generating CSRF token")
			w.WriteHeader(http.StatusInternalServerError)
			return
		}

		viewData["CSRFToken"] = session.Values["csrfToken"]

		renderTemplate(w, "full-site.gohtml", "edit-user.gohtml", TemplateData{
			Request:  req,
			ViewData: viewData,
		})
	}

	if req.Method == http.MethodPost {

		logrus.WithFields(logrus.Fields{
			"user-id":      user.ID,
			"edit-user-id": editUser.ID,
			"remote-addr":  req.RemoteAddr,
		}).Info("User edited user")

		if err := req.ParseForm(); err != nil {
			logrus.WithError(err).Error("Error while parsing form")
			w.WriteHeader(http.StatusBadRequest)
			return
		}

		if _, ok := req.PostForm["reset-2fa"]; ok {

			token := req.PostForm.Get("csrf-token")
			if token != session.Values["csrfToken"].(string) {
				htmlRedirect(w, req, fmt.Sprintf("/users/%d", id), "Invalid CSRF", http.StatusBadRequest)
				return
			}

			//set totpsecret to NULL
			editUser.TOTPSecret.Valid = false
			editUser.TOTPSecret.String = ""

			//TODO session invalidation

			if err := conn.Save(&editUser).Error; err != nil {
				logrus.WithError(err).Error("Error while updating user entity")
				w.WriteHeader(http.StatusInternalServerError)
				return
			}
		}

		if _, ok := req.PostForm["update-password"]; ok {

			token := req.PostForm.Get("csrf-token")
			if token != session.Values["csrfToken"].(string) {
				viewData["Error"] = "Invalid CSRF token, please try again"

				render()
				return
			}

			input := &struct {
				Password        string `validate:"required,strong-password"`
				PasswordConfirm string `validate:"required,eqfield=Password"`
			}{
				Password:        req.FormValue("Password"),
				PasswordConfirm: req.FormValue("PasswordConfirm"),
			}

			//Create a english translator
			en := en.New()

			//Create a universal translator with english as fallback
			uni := ut.New(en, en)

			//Get the english translator
			trans, _ := uni.GetTranslator("en")

			viewData["Translator"] = trans

			//Crate a new validator
			validate := validator.New()

			validate.RegisterValidation("strong-password", strongPasswordValidationFunc)

			//Load default english translations into the english translator
			en_translations.RegisterDefaultTranslations(validate, trans)

			err := validate.Struct(input)
			if err == nil {

				//Hash the password using bcrypt (bcrypt also automatically salts the hash)
				editUser.PasswordHash, err = bcrypt.GenerateFromPassword([]byte(input.Password), viper.GetInt(NewUserPasswordBcryptCost))
				if err != nil {
					//Log the error
					logrus.WithError(err).Error(err)

					//Set user friendly error
					viewData["Error"] = "Unable to save password due to an internal server error"

					render()
					return
				}

				if err := conn.Save(&editUser).Error; err != nil {
					logrus.WithError(err).Error("Error while updating user entity")
					w.WriteHeader(http.StatusInternalServerError)
					return
				}

				viewData["Success"] = "The password has been updated"
			} else {
				formErrors := map[string]validator.FieldError{}
				for _, err := range err.(validator.ValidationErrors) {
					formErrors[err.Field()] = err
				}

				viewData["FormErrors"] = formErrors
			}
		}
	}

	render()
}
