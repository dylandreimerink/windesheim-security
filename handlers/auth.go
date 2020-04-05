package handlers

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"html/template"
	"net/http"
	"net/url"
	"time"

	"github.com/dylandreimerink/windesheim-security/db"
	"github.com/dylandreimerink/windesheim-security/mail"
	"github.com/go-gomail/gomail"
	"github.com/go-playground/locales/en"
	ut "github.com/go-playground/universal-translator"
	"github.com/jinzhu/gorm"
	"github.com/pkg/errors"
	"github.com/pquerna/otp/totp"
	"github.com/sirupsen/logrus"
	"github.com/spf13/viper"
	"golang.org/x/crypto/bcrypt"
	"gopkg.in/go-playground/validator.v9"
	en_translations "gopkg.in/go-playground/validator.v9/translations/en"
)

const (
	NewUserPasswordBcryptCost = "security.user_password_bcrypt_cost"
	GoogleRecaptchaSiteKey    = "security.recaptcha.site_key"
	GoogleRecaptchaSecretKey  = "security.recaptcha.secret_key"
	GoogleRecaptchaCheckURL   = "security.recaptcha.check_url"
)

func init() {
	//Register routes
	Router.HandleFunc("/login", handlerLogin)
	Router.HandleFunc("/login/2fa", handlerLogin2FA)
	Router.HandleFunc("/logout", handlerLogout)
	Router.HandleFunc("/register", handlerRegister)
	Router.HandleFunc("/register-confirm-email", handlerRegisterConfirmEmail)
	Router.HandleFunc("/resend-register-code", handlerResendRegisterCode)
	Router.HandleFunc("/password-reset", handlerPasswordResetRequest)
	Router.HandleFunc("/password-reset/step2", handlerPasswordResetConfirm)
	Router.HandleFunc("/password-reset/step3", handlerPasswordReset)

	//12 seems like a reasonable default number at the moment(2019)
	//https://stackoverflow.com/questions/50468319/which-bcrypt-cost-to-use-for-2018
	viper.SetDefault(NewUserPasswordBcryptCost, 12)
}

func isRecaptchaValid(clientResponse string) bool {
	response, err := http.PostForm(viper.GetString(GoogleRecaptchaCheckURL), url.Values{
		"secret":   []string{viper.GetString(GoogleRecaptchaSecretKey)},
		"response": []string{clientResponse},
	})

	if err != nil {
		logrus.WithError(err).Error("Error while verifying captcha")
		return false
	}

	if response.StatusCode != 200 {
		logrus.WithField("status-code", response.StatusCode).WithField("status", response.Status).Error("Verifying captcha response has a non 200 status code")
		return false
	}

	captchaResponse := struct {
		Success bool `json:"success"`

		// timestamp of the challenge load (ISO format yyyy-MM-dd'T'HH:mm:ssZZ)
		Timestamp string `json:"challenge_ts"`

		// the hostname of the site where the reCAPTCHA was solved
		Hostname string `json:"hostname"`

		ErrorCodes interface{} `json:"error-codes"`
	}{}

	jsonReader := json.NewDecoder(response.Body)
	if err := jsonReader.Decode(&captchaResponse); err != nil {
		logrus.WithError(err).Error("Error while decoding captcha check response")
		return false
	}

	return captchaResponse.Success
}

//Handler a login request
func handlerLogin(w http.ResponseWriter, req *http.Request) {
	session := getSessionFromContext(req.Context())

	if existingUser := getUserFromSession(session); existingUser != nil {
		if existingUser.FirstFactorAuthenticated {
			//Redirect to the second authentication page since the user is already first factor authenticated
			http.Redirect(w, req, getAbsoluteLink(req, "/login/2fa"), http.StatusSeeOther)
		}
	}

	viewData := map[string]interface{}{
		"Error":            "",
		"FormValues":       map[string]string{},
		"RecaptchaSiteKey": viper.GetString(GoogleRecaptchaSiteKey),
	}

	render := func() {
		renderTemplate(w, "simple.gohtml", "login.gohtml", TemplateData{
			Request:  req,
			ViewData: viewData,
		})
	}

	if req.Method == http.MethodPost {

		email := req.FormValue("email")
		password := req.FormValue("password")
		captchaResponse := req.FormValue("g-recaptcha-response")

		viewData["FormValues"] = map[string]string{
			"Email": email,
		}

		if !isRecaptchaValid(captchaResponse) {
			viewData["Error"] = "Invalid captcha, please try again"
			render()
			return
		}

		dbConn, err := db.GetConnection()
		if err != nil {
			viewData["Error"] = "Internal server error, please try again later"
			logrus.WithError(err).Error("Error while getting database connection")
			render()
			return
		}

		user := &db.User{}

		if err := dbConn.Preload("Role").Preload("Role.Permissions").Where("email = ?", email).First(user).Error; err != nil {
			//If the user doesn't exist return a error to the frontend
			if gorm.IsRecordNotFoundError(err) {
				viewData["Error"] = "Invalid email or password"
				render()
				return
			}

			viewData["Error"] = "Internal server error, please try again later"
			logrus.WithError(err).Error("Error while querying user")
			render()
			return
		}

		if user.ID == 0 {
			viewData["Error"] = "Invalid email or password"
			render()
			return
		}

		if !user.Activated {
			viewData["Error"] = template.HTML(fmt.Sprintf(`Your account has not yet been activated. 
				Please activate your account here: <a href="%s">link</a>`,
				getAbsoluteLink(req, "/register-confirm-email"),
			))
			render()
			return
		}

		if user.Archived {
			viewData["Error"] = `Your account has been archived. 
				Contact our helpdesk or system admin to restore your account`
			render()
			return
		}

		if err := bcrypt.CompareHashAndPassword(user.PasswordHash, []byte(password)); err != nil {
			viewData["Error"] = "Invalid email or password"
			render()
			return
		}

		//If the user has a TOTP secret set
		if user.TOTPSecret.Valid {
			//two factor authentication is enabled and the user has to complete the second factor before being authenticated
			user.FirstFactorAuthenticated = true
		} else {
			//else the user if now authenticated
			user.Authenticated = true
		}

		//Save the user in the session
		session.Values["user"] = user

		if user.FirstFactorAuthenticated {
			logrus.WithFields(logrus.Fields{
				"user-id":     user.ID,
				"remote-addr": req.RemoteAddr,
			}).Info("User completed 1FA")

			//Redirect to the second authentication page on successfull first factor authentication
			http.Redirect(w, req, getAbsoluteLink(req, "/login/2fa"), http.StatusSeeOther)

			return
		}

		logrus.WithFields(logrus.Fields{
			"user-id":     user.ID,
			"remote-addr": req.RemoteAddr,
		}).Info("User logged in")

		//Redirect to landing page on successfull login
		http.Redirect(w, req, getAbsoluteLink(req, "/"), http.StatusSeeOther)

		return
	}

	viewData["InfoMessages"] = session.Flashes("info-message")

	render()
}

func handlerLogin2FA(w http.ResponseWriter, req *http.Request) {
	session := getSessionFromContext(req.Context())

	user := getUserFromSession(session)

	//If there is not user linked to the session
	if user == nil {
		//Redirect to the login page for initial login
		http.Redirect(w, req, getAbsoluteLink(req, "/login"), http.StatusSeeOther)
		return
	}

	//If the user is already logged
	if user.Authenticated {
		//Redirect to the landing page
		http.Redirect(w, req, getAbsoluteLink(req, "/"), http.StatusSeeOther)
		return
	}

	if !user.FirstFactorAuthenticated {
		http.Redirect(w, req, getAbsoluteLink(req, "/login"), http.StatusSeeOther)
		return
	}

	viewData := map[string]interface{}{
		"Error": "",
	}

	render := func() {
		renderTemplate(w, "simple.gohtml", "login2fa.gohtml", TemplateData{
			Request:  req,
			ViewData: viewData,
		})
	}

	if req.Method == http.MethodPost {
		code := req.PostFormValue("totp-code")
		if code == "" {
			viewData["Error"] = "missing field 'totp-code'"
			render()
			return
		}

		if totp.Validate(code, user.TOTPSecret.String) {
			logrus.WithFields(logrus.Fields{
				"user-id":     user.ID,
				"remote-addr": req.RemoteAddr,
			}).Info("User completed 2FA and is now logged in")

			user.Authenticated = true

			http.Redirect(w, req, getAbsoluteLink(req, "/"), http.StatusSeeOther)
			return
		} else {
			logrus.WithFields(logrus.Fields{
				"user-id":     user.ID,
				"remote-addr": req.RemoteAddr,
			}).Info("User failed 2FA check")

			user.FirstFactorAuthenticated = false

			http.Redirect(w, req, getAbsoluteLink(req, "/login"), http.StatusSeeOther)
			return
		}

	}

	render()
}

func handlerLogout(w http.ResponseWriter, req *http.Request) {
	session := getSessionFromContext(req.Context())

	user := getUserFromSession(session)
	if user != nil {
		//Clear the user variable
		session.Values["user"] = &db.User{
			Authenticated: false,
		}

		//Destroy the session
		session.Options.MaxAge = -1
	}

	renderTemplate(w, "simple.gohtml", "logout.gohtml", TemplateData{
		Request: req,
	})
}

func handlerRegister(w http.ResponseWriter, req *http.Request) {

	viewData := map[string]interface{}{
		"Error":            "",
		"FormErrors":       map[string]string{},
		"FormValues":       map[string]string{},
		"RecaptchaSiteKey": viper.GetString(GoogleRecaptchaSiteKey),
	}

	processError := func(userError, debugError string, err error) {
		//Log the error
		logrus.WithError(err).Error(debugError)

		//Set user friendly error
		viewData["Error"] = userError

		//Render the template
		renderTemplate(w, "simple.gohtml", "register.gohtml", TemplateData{
			Request:  req,
			ViewData: viewData,
		})
	}

	if req.Method == http.MethodPost {

		input := &struct {
			FirstName       string `validate:"required"`
			LastName        string `validate:"required"`
			Email           string `validate:"required,email"`
			EmailConfirm    string `validate:"required,email,eqfield=Email"`
			Password        string `validate:"required,strong-password"`
			PasswordConfirm string `validate:"required,eqfield=Password"`
		}{
			FirstName:       req.FormValue("FirstName"),
			LastName:        req.FormValue("LastName"),
			Email:           req.FormValue("Email"),
			EmailConfirm:    req.FormValue("EmailConfirm"),
			Password:        req.FormValue("Password"),
			PasswordConfirm: req.FormValue("PasswordConfirm"),
		}

		viewData["FormValues"] = map[string]string{
			"FirstName": input.FirstName,
			"LastName":  input.LastName,
			"Email":     input.Email,
		}

		if !isRecaptchaValid(req.FormValue("g-recaptcha-response")) {
			viewData["Error"] = "Captcha invalid, try again"

			//Render the template
			renderTemplate(w, "simple.gohtml", "register.gohtml", TemplateData{
				Request:  req,
				ViewData: viewData,
			})
			return
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

			//TODO duplicate email check

			//Hash the password using bcrypt (bcrypt also automatically salts the hash)
			hashedPassword, err := bcrypt.GenerateFromPassword([]byte(input.Password), viper.GetInt(NewUserPasswordBcryptCost))
			if err != nil {
				//Process the error
				processError("Error while creating user account", "Error while hashing password for new user", err)

				//Stop processing request
				return
			}

			//Create a new user model
			user := &db.User{
				FirstName:    input.FirstName,
				LastName:     input.LastName,
				Email:        input.Email,
				PasswordHash: hashedPassword,
			}

			conn, err := db.GetConnection()
			if err != nil {
				processError("Error while creating user account", "Error while creating connection to database", err)

				return
			}

			if err := conn.Save(user).Error; err != nil {
				processError("Error while creating user account", "Error while creating user", err)

				return
			}

			logrus.WithFields(logrus.Fields{
				"user-id":     user.ID,
				"remote-addr": req.RemoteAddr,
			}).Info("New user registered")

			if err := sendActivationCode(user, conn); err != nil {
				processError("Error while creating activation code", "Error while creating user", err)

				return
			}

			//Get the current schema
			schema := "http"
			if req.TLS != nil {
				schema += "s"
			}

			//Redirect to the confirm email page
			http.Redirect(w, req, fmt.Sprintf("%s://%s%s", schema, req.Host, "/register-confirm-email"), http.StatusSeeOther)

			return

		} else {
			formErrors := map[string]validator.FieldError{}
			for _, err := range err.(validator.ValidationErrors) {
				formErrors[err.Field()] = err
			}

			viewData["FormErrors"] = formErrors
		}
	}

	renderTemplate(w, "simple.gohtml", "register.gohtml", TemplateData{
		Request:  req,
		ViewData: viewData,
	})
}

func handlerRegisterConfirmEmail(w http.ResponseWriter, req *http.Request) {
	viewData := map[string]interface{}{}

	session := getSessionFromContext(req.Context())

	render := func() {
		renderTemplate(w, "simple.gohtml", "register-confirm-email.gohtml", TemplateData{
			Request:  req,
			ViewData: viewData,
		})
	}

	if code := req.URL.Query().Get("confirmation-code"); code != "" {
		dbConn, err := db.GetConnection()
		if err != nil {
			viewData["Error"] = "Internal server error, please try again later"
			logrus.WithError(err).Error("Error while getting database connection")
			render()
			return
		}

		activationCode := &db.UserActivationCode{}

		dbConn.LogMode(true)

		if err := dbConn.Preload("User").Where("code = ?", code).First(activationCode).Error; err != nil {

			if gorm.IsRecordNotFoundError(err) {
				viewData["Error"] = "Invalid confirmation code"
				render()
				return
			}

			viewData["Error"] = "Internal server error, please try again later"
			logrus.WithError(err).Error("Error while getting activation code")
			render()
			return
		}

		activationCode.User.Activated = true

		if err := dbConn.Save(activationCode.User).Error; err != nil {
			viewData["Error"] = "Internal server error, please try again later"
			logrus.WithError(err).Error("Error while activating user")
			render()
			return
		}

		logrus.WithFields(logrus.Fields{
			"user-id":     activationCode.ID,
			"remote-addr": req.RemoteAddr,
		}).Info("User activated account")

		if err := dbConn.Delete(activationCode).Error; err != nil {
			viewData["Error"] = "Internal server error, please try again later"
			logrus.WithError(err).Error("Error while deleting activation code")
			render()
			return
		}

		schema := "http"
		if req.TLS != nil {
			schema += "s"
		}

		session.AddFlash("Account has been activated", "info-message")

		//Redirect to the login page
		http.Redirect(w, req, fmt.Sprintf("%s://%s%s", schema, req.Host, "/login"), http.StatusSeeOther)
	}

	viewData["InfoMessages"] = session.Flashes("info-message")

	render()
}

func handlerPasswordResetConfirm(w http.ResponseWriter, req *http.Request) {
	viewData := map[string]interface{}{
		"Error":            "",
		"FormErrors":       map[string]string{},
		"FormValues":       map[string]string{},
		"RecaptchaSiteKey": viper.GetString(GoogleRecaptchaSiteKey),
	}

	render := func() {
		renderTemplate(w, "simple.gohtml", "reset-password-confirm.gohtml", TemplateData{
			Request:  req,
			ViewData: viewData,
		})
	}

	if req.Method == http.MethodPost {

		if err := req.ParseForm(); err != nil {
			viewData["Error"] = "Internal server error, please try again later"
			logrus.WithError(err).Error("Error parsing form")
			render()
			return
		}

		if !isRecaptchaValid(req.FormValue("g-recaptcha-response")) {
			viewData["Error"] = "Invalid captcha, try again"
			render()
			return
		}

		code := req.PostForm.Get("confirmation-code")

		dbConn, err := db.GetConnection()
		if err != nil {
			viewData["Error"] = "Internal server error, please try again later"
			logrus.WithError(err).Error("Error while getting database connection")
			render()
			return
		}

		resetCode := &db.PasswordResetCode{}

		dbConn.LogMode(true)

		if err := dbConn.Preload("User").Where("code = ?", code).First(resetCode).Error; err != nil {

			if gorm.IsRecordNotFoundError(err) {
				viewData["Error"] = "Invalid confirmation code"
				render()
				return
			}

			viewData["Error"] = "Internal server error, please try again later"
			logrus.WithError(err).Error("Error while getting reset code")
			render()
			return
		}

		//If valid until is in the past
		if time.Until(resetCode.ValidUntil) < 0 {
			viewData["Error"] = "Code expired, please create a new request"
			render()
			return
		}

		session := getSessionFromContext(req.Context())
		session.Values["user"] = resetCode.User
		session.Values["password-reset-valid"] = time.Now().Format(time.RFC3339)

		logrus.WithFields(logrus.Fields{
			"user-id":     resetCode.User.ID,
			"remote-addr": req.RemoteAddr,
		}).Info("User confirmed password reset with code")

		if err := dbConn.Delete(resetCode).Error; err != nil {
			viewData["Error"] = "Internal server error, please try again later"
			logrus.WithError(err).Error("Error while deleting reset code")
			render()
			return
		}

		schema := "http"
		if req.TLS != nil {
			schema += "s"
		}

		//Redirect to the login page
		http.Redirect(w, req, fmt.Sprintf("%s://%s%s", schema, req.Host, "/password-reset/step3"), http.StatusSeeOther)
	}

	render()
}

func handlerPasswordReset(w http.ResponseWriter, req *http.Request) {
	viewData := map[string]interface{}{
		"Error":      "",
		"FormErrors": map[string]string{},
		"FormValues": map[string]string{},
	}

	render := func() {
		renderTemplate(w, "simple.gohtml", "reset-password.gohtml", TemplateData{
			Request:  req,
			ViewData: viewData,
		})
	}

	schema := "http"
	if req.TLS != nil {
		schema += "s"
	}

	session := getSessionFromContext(req.Context())
	timeInt := session.Values["password-reset-valid"]
	if timeInt == nil {
		http.Redirect(w, req, fmt.Sprintf("%s://%s%s", schema, req.Host, "/password-reset"), http.StatusTemporaryRedirect)
		return
	}

	//Only continue if the time when the reset token was confirmed was less then 10 minutes ago
	if timeStr, ok := timeInt.(string); ok {
		if createdTime, err := time.Parse(time.RFC3339, timeStr); err == nil {
			if time.Since(createdTime) > (10 * time.Minute) {
				http.Redirect(w, req, fmt.Sprintf("%s://%s%s", schema, req.Host, "/password-reset"), http.StatusTemporaryRedirect)
				return
			}
		} else {
			http.Redirect(w, req, fmt.Sprintf("%s://%s%s", schema, req.Host, "/password-reset"), http.StatusTemporaryRedirect)
			return
		}
	} else {
		http.Redirect(w, req, fmt.Sprintf("%s://%s%s", schema, req.Host, "/password-reset"), http.StatusTemporaryRedirect)
		return
	}

	user := getUserFromSession(session)
	if user == nil {
		http.Redirect(w, req, fmt.Sprintf("%s://%s%s", schema, req.Host, "/password-reset"), http.StatusTemporaryRedirect)
		return
	}

	if req.Method == http.MethodPost {
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
			hashedPassword, err := bcrypt.GenerateFromPassword([]byte(input.Password), viper.GetInt(NewUserPasswordBcryptCost))
			if err != nil {
				logrus.WithError(err).Error("Error while hashing password for new user")

				viewData["Error"] = "Error while resetting password"
				render()

				//Stop processing request
				return
			}

			conn, err := db.GetConnection()
			if err != nil {
				logrus.WithError(err).Error("Error while creating connection to database")

				viewData["Error"] = "Error while resetting password"
				render()

				return
			}

			var dbUser db.User
			if err := conn.First(&dbUser, "id = ?", user.ID).Error; err != nil {
				logrus.WithError(err).Error("Error while getting user from database")

				viewData["Error"] = "Error while resetting password"
				render()

				return
			}

			dbUser.PasswordHash = hashedPassword

			if err := conn.Save(&dbUser).Error; err != nil {
				logrus.WithError(err).Error("Error while updating user password")

				viewData["Error"] = "Error while resetting password"
				render()

				return
			}

			logrus.WithFields(logrus.Fields{
				"user-id":     user.ID,
				"remote-addr": req.RemoteAddr,
			}).Info("User completed password reset")

			//Get the current schema
			schema := "http"
			if req.TLS != nil {
				schema += "s"
			}

			//Redirect to the confirm email page
			http.Redirect(w, req, fmt.Sprintf("%s://%s%s", schema, req.Host, "/login"), http.StatusSeeOther)

			return

		} else {
			formErrors := map[string]validator.FieldError{}
			for _, err := range err.(validator.ValidationErrors) {
				formErrors[err.Field()] = err
			}

			viewData["FormErrors"] = formErrors
		}
	}

	render()
}

func handlerPasswordResetRequest(w http.ResponseWriter, req *http.Request) {
	viewData := map[string]interface{}{
		"Error":            "",
		"FormErrors":       map[string]string{},
		"FormValues":       map[string]string{},
		"RecaptchaSiteKey": viper.GetString(GoogleRecaptchaSiteKey),
	}

	render := func() {
		renderTemplate(w, "simple.gohtml", "reset-password-request.gohtml", TemplateData{
			Request:  req,
			ViewData: viewData,
		})
	}

	if req.Method == http.MethodPost {

		if !isRecaptchaValid(req.FormValue("g-recaptcha-response")) {
			viewData["Error"] = "Invalid captcha, try again"
			render()
			return
		}

		input := &struct {
			Email string `validate:"required,email"`
		}{
			Email: req.FormValue("Email"),
		}

		//Create a english translator
		en := en.New()

		//Create a universal translator with english as fallback
		uni := ut.New(en, en)

		//Get the english translator
		trans, _ := uni.GetTranslator("en")

		//Crate a new validator
		validate := validator.New()

		//Load default english translations into the english translator
		en_translations.RegisterDefaultTranslations(validate, trans)

		err := validate.Struct(input)
		if err == nil {
			dbConn, err := db.GetConnection()
			if err != nil {
				viewData["Error"] = "Internal server error, please try again later"
				logrus.WithError(err).Error("Error while getting database connection")
				render()
				return
			}

			user := &db.User{}

			if err := dbConn.Where("email = ?", input.Email).First(user).Error; err != nil {
				viewData["Error"] = "Internal server error, please try again later"
				logrus.WithError(err).Error("Error while querying user")
				render()
				return
			}

			if user.ID == 0 {
				viewData["Error"] = "Unable to reset password, please contact our helpdesk or system admin to assist you"
				render()
				return
			}

			if !user.Activated {
				viewData["Error"] = "Unable to reset password, please contact our helpdesk or system admin to assist you"
				render()
				return
			}

			if user.Archived {
				viewData["Error"] = "Unable to reset password, please contact our helpdesk or system admin to assist you"
				render()
				return
			}

			//TODO add rate limit

			if err := sendPasswordResetCode(user, dbConn); err != nil {
				viewData["Error"] = "Internal server error, please try again later"
				logrus.WithError(err).Error("Error while sending password reset mail")
				render()
				return
			}

			logrus.WithFields(logrus.Fields{
				"user-id":     user.ID,
				"remote-addr": req.RemoteAddr,
			}).Info("Password reset requested for user")

			schema := "http"
			if req.TLS != nil {
				schema += "s"
			}

			//Redirect to reset code input page
			http.Redirect(w, req, fmt.Sprintf("%s://%s%s", schema, req.Host, "/password-reset/step2"), http.StatusSeeOther)

		} else {
			viewData["FormErrors"] = err.(validator.ValidationErrors).Translate(trans)
		}
	}

	render()
}

func handlerResendRegisterCode(w http.ResponseWriter, req *http.Request) {
	viewData := map[string]interface{}{
		"Error":      "",
		"FormErrors": map[string]string{},
		"FormValues": map[string]string{},
	}

	render := func() {
		renderTemplate(w, "simple.gohtml", "resend-register-code.gohtml", TemplateData{
			Request:  req,
			ViewData: viewData,
		})
	}

	if req.Method == http.MethodPost {
		input := &struct {
			Email string `validate:"required,email"`
		}{
			Email: req.FormValue("Email"),
		}

		//Create a english translator
		en := en.New()

		//Create a universal translator with english as fallback
		uni := ut.New(en, en)

		//Get the english translator
		trans, _ := uni.GetTranslator("en")

		//Crate a new validator
		validate := validator.New()

		//Load default english translations into the english translator
		en_translations.RegisterDefaultTranslations(validate, trans)

		err := validate.Struct(input)
		if err == nil {
			dbConn, err := db.GetConnection()
			if err != nil {
				viewData["Error"] = "Internal server error, please try again later"
				logrus.WithError(err).Error("Error while getting database connection")
				render()
				return
			}

			user := &db.User{}

			if err := dbConn.Where("email = ?", input.Email).First(user).Error; err != nil {
				viewData["Error"] = "Internal server error, please try again later"
				logrus.WithError(err).Error("Error while querying user")
				render()
				return
			}

			if user.ID == 0 {
				viewData["Error"] = "This email address is not registered or already activated"
				render()
				return
			}

			if user.Activated {
				viewData["Error"] = "This email address is not registered or already activated"
				render()
				return
			}

			//TODO add rate limit

			err = sendActivationCode(user, dbConn)
			if err != nil {
				viewData["Error"] = err
				render()
				return
			}

			logrus.WithFields(logrus.Fields{
				"user-id":     user.ID,
				"remote-addr": req.RemoteAddr,
			}).Info("Account activation code resent")

			session := getSessionFromContext(req.Context())

			session.AddFlash("Confirmation email has been resent", "info-message")

			schema := "http"
			if req.TLS != nil {
				schema += "s"
			}

			//Redirect to the confirm email page
			http.Redirect(w, req, fmt.Sprintf("%s://%s%s", schema, req.Host, "/register-confirm-email"), http.StatusSeeOther)

		} else {
			viewData["FormErrors"] = err.(validator.ValidationErrors).Translate(trans)
		}
	}

	render()
}

func sendActivationCode(user *db.User, dbConn *gorm.DB) error {
	activationMail := gomail.NewMessage()

	activationCodeBytes := make([]byte, 16)
	_, err := rand.Read(activationCodeBytes)
	if err != nil {
		logrus.WithError(err).Error("Error generating activation code")
		return errors.New("Unable to send activation mail, please try again later")
	}

	userOldActivationCodes := []db.UserActivationCode{}

	if err := dbConn.Model(user).Related(&userOldActivationCodes, "ActivationCodes").Error; err != nil {
		logrus.WithError(err).Error("Error while querying old activation codes")
		return errors.New("Unable to send activation mail, please try again later")
	}

	for _, oldCode := range userOldActivationCodes {
		if err := dbConn.Delete(&oldCode).Error; err != nil {
			logrus.WithError(err).Error("Error while invalidating old activation codes")
			return errors.New("Unable to send activation mail, please try again later")
		}
	}

	activationCode := base64.RawURLEncoding.EncodeToString(activationCodeBytes)

	activationCodeModel := &db.UserActivationCode{
		Code:       activationCode,
		ValidUntil: time.Now().Add(time.Hour * 24), //TODO make token validation period configurable
		User:       *user,
	}

	if err := dbConn.Save(activationCodeModel).Error; err != nil {
		logrus.WithError(err).Error("Error while inserting activation code in database")
		return errors.New("Unable to send activation mail, please try again later")
	}

	activationMail.SetHeader("From", "noreply@winnote.nl")
	activationMail.SetAddressHeader("To", user.Email, fmt.Sprintf("%s %s", user.FirstName, user.LastName))
	activationMail.SetHeader("Subject", "Account activation code")
	activationMail.SetBody("text/html", fmt.Sprintf(`Dear %s %s,
<p>Thank you for creating a account at winnote.nl. To activate your account please click this <a href="http://winnote.nl/register-confirm-email?confirmation-code=%s">link</a>.
Or enter the following activation code at winnote.nl/register-confirm-email.</p>
<p><b>%s</b></p>
<p>
Kind regards,
winnote.nl</>`, user.FirstName, user.LastName, activationCode, activationCode))

	mailClient := mail.GetMailClient()
	if err := mailClient.DialAndSend(activationMail); err != nil {
		logrus.WithError(err).Error("Error while sending mail")
		return errors.New("Unable to send activation mail, please try again later")
	}

	return nil
}

func sendPasswordResetCode(user *db.User, dbConn *gorm.DB) error {
	resetMail := gomail.NewMessage()

	resetCodeBytes := make([]byte, 16)
	_, err := rand.Read(resetCodeBytes)
	if err != nil {
		logrus.WithError(err).Error("Error generating password reset code")
		return errors.New("Unable to send password reset mail, please try again later")
	}

	userOldResetCodes := []db.PasswordResetCode{}

	if err := dbConn.Model(user).Related(&userOldResetCodes, "PasswordResetCodes").Error; err != nil {
		logrus.WithError(err).Error("Error while querying old activation codes")
		return errors.New("Unable to send activation mail, please try again later")
	}

	for _, oldCode := range userOldResetCodes {
		if err := dbConn.Delete(&oldCode).Error; err != nil {
			logrus.WithError(err).Error("Error while invalidating old password reset codes")
			return errors.New("Unable to send password reset mail, please try again later")
		}
	}

	resetCode := base64.RawURLEncoding.EncodeToString(resetCodeBytes)

	resetCodeModel := &db.PasswordResetCode{
		Code:       resetCode,
		ValidUntil: time.Now().Add(time.Minute * 30), //TODO make token validation period configurable
		User:       *user,
	}

	if err := dbConn.Save(resetCodeModel).Error; err != nil {
		logrus.WithError(err).Error("Error while inserting reset code in database")
		return errors.New("Unable to send password reset mail, please try again later")
	}

	resetMail.SetHeader("From", "noreply@winnote.nl")
	resetMail.SetAddressHeader("To", user.Email, fmt.Sprintf("%s %s", user.FirstName, user.LastName))
	resetMail.SetHeader("Subject", "Account password reset")
	resetMail.SetBody("text/html", fmt.Sprintf(`Dear %s %s,
<p>A password reset has been requested for your account. If you didn't request a password reset please ignore this email. If you did please enter the following code at <a href="winnote.nl/password-reset/step2">winnote.nl/password-reset/step2</a> .</p>
<p><b>%s</b></p>
<p>
Kind regards,
winnote.nl</>`, user.FirstName, user.LastName, resetCode))

	mailClient := mail.GetMailClient()
	if err := mailClient.DialAndSend(resetMail); err != nil {
		logrus.WithError(err).Error("Error while sending mail")
		return errors.New("Unable to send password reset mail, please try again later")
	}

	return nil
}
