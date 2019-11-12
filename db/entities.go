package db

import (
	"encoding/json"
	"time"

	"github.com/jinzhu/gorm"
)

func init() {
	//Add the user model to the registered models
	registeredModels = append(registeredModels,
		&User{},
		&UserActivationCode{},
		&Organization{},
		&OrganizationMember{},
		&OrganizationRole{},
		&OrganizationRolePermission{},
		&Appointment{},
		&AppointmentInvitations{},
	)
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

	//The 2FA mode. Can be: none, totp or u2f
	TwoFactorAuthenticationMode string `gorm:"not null;default:'none'"`

	//The TOTP secret
	TOTPSecret string `grom:"null"`

	//The U2F secret
	U2FSecret string `grom:"null"`

	//If true, it signals the user has completed the first login factor of the two factor authentication
	//This field is only used when TwoFactorAuthenticationMode is not 'none'
	//This field is not part of the database table
	FirstFactorAuthenticated bool `gorm:"-"`

	//If true, it signals the user is currently logged in
	//This field is not part of the database table
	Authenticated bool `gorm:"-"`

	ActivationCodes []UserActivationCode

	Appointments []Appointment

	Organizations []Organization
}

type UserActivationCode struct {
	gorm.Model

	ValidUntil time.Time
	Code       string `gorm:"not null"`
	User       User   `gorm:"foreignkey:UserID"`
	UserID     int
}

type Organization struct {
	gorm.Model

	//The name of the organization
	Name string `gorm:"not null"`
}

type OrganizationMember struct {
	gorm.Model

	//The organization member
	Member   User `gorm:"foreignkey:MemberID"`
	MemberID int

	//The organization
	Organization   Organization `gorm:"foreignkey:OrganizationID"`
	OrganizationID int

	//The role the member has in this organization
	OrganizationRole   OrganizationRole `gorm:"foreignkey:OrganizationRoleID"`
	OrganizationRoleID int
}

type OrganizationRole struct {
	gorm.Model

	//Name of the role
	Name string `gorm:"not null"`
}

type OrganizationRolePermission struct {
	gorm.Model

	//The organizationRole which has this permission
	OrganizationRole   OrganizationRole `gorm:"foreignkey:OrganizationRoleID"`
	OrganizationRoleID int

	//The key of the permission
	PermissionKey string `gorm:"not null"`
}

type Appointment struct {
	gorm.Model

	Title          string `gorm:"not null"`
	Description    string `gorm:"null"`
	StartTime      time.Time
	EndTime        time.Time
	Location       string `gorm:"null"`
	Owner          User   `gorm:"foreignkey:OwnerID"`
	OwnerID        int
	Organization   Organization `gorm:"foreignkey:OrganizationID"`
	OrganizationID int
}

func (appointment *Appointment) MarshalJSON() ([]byte, error) {
	return json.Marshal(
		map[string]interface{}{
			"id":          appointment.ID,
			"start":       appointment.StartTime.Format(time.RFC3339),
			"end":         appointment.EndTime.Format(time.RFC3339),
			"title":       appointment.Title,
			"description": appointment.Description,
			"location":    appointment.Location,
		},
	)
}

type AppointmentInvitations struct {
	gorm.Model

	Invitee       User `gorm:"foreignkey:InviteeID"`
	InviteeID     int
	Appointment   Appointment `gorm:"foreignkey:AppointmentID"`
	AppointmentID int
	Accepted      bool
}
