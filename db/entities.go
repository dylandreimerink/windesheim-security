package db

import (
	"time"

	"github.com/jinzhu/gorm"
)

func init() {
	//Add the user model to the registered models
	registeredModels = append(registeredModels, &User{}, &UserActivationCode{})
}

//User is the model representing a user in this application
type User struct {
	gorm.Model

	//Basic user information
	Email               string    `gorm:"not null;unique_index"`
	PasswordHash        []byte    `gorm:"not null"`
	FirstName, LastName string    `gorm:"not null"`
	Birthday            time.Time `gorm:"not null;default:now()"`

	//Is set to true after email confirmation
	Activated bool `gorm:"not null;default:false"`

	//If true, it signals the user is currently logged in
	//This field is not part of the database table
	Authenticated bool `gorm:"-"`

	ActivationCodes []UserActivationCode
}

type UserActivationCode struct {
	gorm.Model

	ValidUntil time.Time
	Code       string `gorm:"not null"`
	User       User   `gorm:"foreignkey:UserID"`
	UserID     int
}
