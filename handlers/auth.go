package handlers

import (
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"html/template"
	"net/http"
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

const NewUserPasswordBcryptCost = "security.user_password_bcrypt_cost"

func init() {
	//Register routes
	Router.HandleFunc("/login", handlerLogin)
	Router.HandleFunc("/login/2fa", handlerLogin2FA)
	Router.HandleFunc("/logout", handlerLogout)
	Router.HandleFunc("/register", handlerRegister)
	Router.HandleFunc("/register-confirm-email", handlerRegisterConfirmEmail)
	Router.HandleFunc("/resend-register-code", handlerResendRegisterCode)

	//12 seems like a reasonable default number at the moment(2019)
	//https://stackoverflow.com/questions/50468319/which-bcrypt-cost-to-use-for-2018
	viper.SetDefault(NewUserPasswordBcryptCost, 12)
}

//Handler a login request
func handlerLogin(w http.ResponseWriter, req *http.Request) {
	session := getSessionFromContext(req.Context())

	viewData := map[string]interface{}{
		"Error":      "",
		"FormValues": map[string]string{},
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

		viewData["FormValues"] = map[string]string{
			"Email": email,
		}

		dbConn, err := db.GetConnection()
		if err != nil {
			viewData["Error"] = "Internal server error, please try again later"
			logrus.WithError(err).Error("Error while getting database connection")
			render()
			return
		}

		user := &db.User{}

		if err := dbConn.Where("email = ?", email).First(user).Error; err != nil {
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

		if err := bcrypt.CompareHashAndPassword(user.PasswordHash, []byte(password)); err != nil {
			viewData["Error"] = "Invalid email or password"
			render()
			return
		}

		//If the user has only one factor authentication this is enough
		if user.TwoFactorAuthenticationMode == "none" {
			//The user if now authenticated
			user.Authenticated = true
		} else {
			//Else two factor authentication is enabled and the user has to complete the second factor before being authenticated
			user.FirstFactorAuthenticated = true
		}

		//Save the user in the session
		session.Values["user"] = user

		if user.FirstFactorAuthenticated {
			//Redirect to the second authentication page on successfull first factor authentication
			http.Redirect(w, req, getAbsoluteLink(req, "/login/2fa"), http.StatusSeeOther)
		}

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

	//If the user is already logged
	if user.Authenticated {
		//Redirect to the second authentication page on successfull first factor authentication
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
		if user.TwoFactorAuthenticationMode == "totp" {
			code := req.PostFormValue("totp-code")
			if code == "" {
				viewData["Error"] = "missing field 'totp-code'"
				render()
				return
			}

			if totp.Validate(code, user.TOTPSecret) {
				user.Authenticated = true

				http.Redirect(w, req, getAbsoluteLink(req, "/"), http.StatusSeeOther)
				return
			} else {
				user.FirstFactorAuthenticated = false

				http.Redirect(w, req, getAbsoluteLink(req, "/login"), http.StatusSeeOther)
				return
			}
		} else {
			http.Error(w, "2FA methods other than totp are not yet supported", http.StatusNotImplemented)
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
		"Error":      "",
		"FormErrors": map[string]string{},
		"FormValues": map[string]string{},
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
			Birthday        string `validate:"required,birthday"`
			Email           string `validate:"required,email"`
			EmailConfirm    string `validate:"required,email,eqfield=Email"`
			Password        string `validate:"required"`
			PasswordConfirm string `validate:"required,eqfield=Password"`
		}{
			FirstName:       req.FormValue("FirstName"),
			LastName:        req.FormValue("LastName"),
			Birthday:        req.FormValue("Birthday"),
			Email:           req.FormValue("Email"),
			EmailConfirm:    req.FormValue("EmailConfirm"),
			Password:        req.FormValue("Password"),
			PasswordConfirm: req.FormValue("PasswordConfirm"),
		}

		viewData["FormValues"] = map[string]string{
			"FirstName": input.FirstName,
			"LastName":  input.LastName,
			"Birthday":  input.Birthday,
			"Email":     input.Email,
		}

		//Create a english translator
		en := en.New()

		//Create a universal translator with english as fallback
		uni := ut.New(en, en)

		//Get the english translator
		trans, _ := uni.GetTranslator("en")

		//Crate a new validator
		validate := validator.New()

		//Add a validation rule for birthdays
		validate.RegisterValidation("birthday", func(fl validator.FieldLevel) bool {
			birthdayString := fl.Field().String()
			birthdayDate, err := time.Parse("2-1-2006", birthdayString)
			if err != nil {
				return false
			}

			//If the birthday is in the future
			if birthdayDate.Sub(time.Now()) > 0 {
				return false
			}

			return true
		})

		//Add error message for birthday validation rule
		validate.RegisterTranslation("birthday", trans, func(ut ut.Translator) error {
			return ut.Add("birthday", "{0} must be a d-m-y formated date in the past", false)
		}, func(ut ut.Translator, fe validator.FieldError) string {
			t, _ := ut.T("birthday", fe.Field())

			return t
		})

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

			birthday, err := time.Parse("2-1-2006", input.Birthday)
			if err != nil {
				processError("Error birthday is incorrect", "Error while parsing birthday after validation", err)

				return
			}

			//Create a new user model
			user := &db.User{
				FirstName:    input.FirstName,
				LastName:     input.LastName,
				Email:        input.Email,
				Birthday:     birthday,
				PasswordHash: hashedPassword,
			}

			conn, err := db.GetConnection()
			if err != nil {
				processError("Error while creating user account", "Error while creating connection to database", err)

				return
			}

			if err := conn.Create(user).Error; err != nil {
				processError("Error while creating user account", "Error while creating user", err)

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
			viewData["FormErrors"] = err.(validator.ValidationErrors).Translate(trans)
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

	activationCode := base64.URLEncoding.EncodeToString(activationCodeBytes)

	activationCodeModel := &db.UserActivationCode{
		Code:       activationCode,
		ValidUntil: time.Now().Add(time.Hour * 24), //TODO make token validation period configurable
		User:       *user,
	}

	if err := dbConn.Save(activationCodeModel).Error; err != nil {
		logrus.WithError(err).Error("Error while inserting activation code in database")
		return errors.New("Unable to send activation mail, please try again later")
	}

	activationMail.SetHeader("From", "noreply@winappoint.nl")
	activationMail.SetAddressHeader("To", user.Email, fmt.Sprintf("%s %s", user.FirstName, user.LastName))
	activationMail.SetHeader("Subject", "Account activation code")
	activationMail.SetBody("text/html", fmt.Sprintf(`Dear %s %s,
<p>Thank you for creating a account at winappoint.nl. To activate your account please click this <a href="http://winappoint.nl/register-confirm-email?confirmation-code=%s">link</a>.
Or enter the following activation code at winappoint.nl/register-confirm-email.</p>
<p><b>%s</b></p>
<p>
Kind regards,
winappoint.nl</>`, user.FirstName, user.LastName, activationCode, activationCode))

	mailClient := mail.GetMailClient()
	if err := mailClient.DialAndSend(activationMail); err != nil {
		logrus.WithError(err).Error("Error while sending mail")
		return errors.New("Unable to send activation mail, please try again later")
	}

	return nil
}
