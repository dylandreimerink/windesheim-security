package db

import (
	"database/sql"
	"time"

	"github.com/jinzhu/gorm"
)

func init() {
	//Add the user model to the registered models
	registeredModels = append(registeredModels,
		&User{},
		&UserActivationCode{},
		&PasswordResetCode{},
		&Role{},
		&Permission{},
		&Note{},
	)
}

//User is the model representing a user in this application
type User struct {
	gorm.Model

	//Basic user information
	Email               string `gorm:"not null;unique_index"`
	PasswordHash        []byte `gorm:"not null"`
	FirstName, LastName string `gorm:"not null"`

	// If true the accounts email has been verified
	Activated bool `gorm:"not null;default:false"`

	// If true the user as been archived by an admin
	Archived bool `gorm:"not null;default:false"`

	//The TOTP secret
	TOTPSecret sql.NullString `grom:"null"`

	//If true, it signals the user has completed the first login factor of the two factor authentication
	//This field is only used when TwoFactorAuthenticationMode is not 'none'
	//This field is not part of the database table
	FirstFactorAuthenticated bool `gorm:"-"`

	//If true, it signals the user is currently logged in
	//This field is not part of the database table
	Authenticated bool `gorm:"-"`

	UserActivationCodes []UserActivationCode

	PasswordResetCodes []PasswordResetCode

	Role   Role `gorm:"foreignkey:RoleID"`
	RoleID int
}

//HasPermssion returns true if the user has the specified permission
func (user *User) HasPermssion(permission PermissionKey) bool {
	for _, rolePermission := range user.Role.Permissions {
		if rolePermission.Permission == permission {
			return true
		}
	}
	return false
}

//HasOneOfPermssions returns true if the user has any of the specified permissions
func (user *User) HasOneOfPermssions(permissions []PermissionKey) bool {

	for _, rolePermission := range user.Role.Permissions {
		for _, askedPermission := range permissions {
			if rolePermission.Permission == askedPermission {
				return true
			}
		}
	}

	return false
}

type PasswordResetCode struct {
	gorm.Model

	ValidUntil time.Time
	Code       string `gorm:"not null"`
	User       User   `gorm:"foreignkey:UserID"`
	UserID     int
}

type UserActivationCode struct {
	gorm.Model

	ValidUntil time.Time
	Code       string `gorm:"not null"`
	User       User   `gorm:"foreignkey:UserID"`
	UserID     int
}

type Role struct {
	gorm.Model

	//Name of the role
	Name string `gorm:"not null"`

	Permissions []Permission
}

type Permission struct {
	gorm.Model

	Role   Role `gorm:"foreignkey:RoleID"`
	RoleID int

	Permission PermissionKey
}

type PermissionKey string

const (
	PERMISSION_CREATE_USER                PermissionKey = "CREATE_USER"
	PERMISSION_READ_USER                                = "READ_USER"
	PERMISSION_UPDATE_USER_PASSWORD                     = "UPDATE_USER_PASSWORD"
	PERMISSION_UPDATE_USER_PASSWORD_RESET               = "UPDATE_USER_PASSWORD_RESET"
	PERMISSION_UPDATE_USER_TOTP                         = "UPDATE_USER_TOTP"
	PERMISSION_DELETE_USER                              = "DELETE_USER"
	PERMISSION_ARCHIVE_USER                             = "ARCHIVE_USER"
)

type Note struct {
	gorm.Model

	Title   string `gorm:"not null"`
	Value   string
	Owner   User `gorm:"foreignkey:OwnerID"`
	OwnerID int
}
