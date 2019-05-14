package mail

import (
	"github.com/go-gomail/gomail"
	"github.com/spf13/viper"
)

const (
	SMTPHostnameConfigKey = "email.smtp.hostname"
	SMTPPortConfigKey     = "email.smtp.port"
	SMTPUsernameConfigKey = "email.smtp.username"
	SMTPPasswordConfigKey = "email.smtp.password"
)

func GetMailClient() *gomail.Dialer {
	dialer := gomail.NewDialer(
		viper.GetString(SMTPHostnameConfigKey),
		viper.GetInt(SMTPPortConfigKey),
		viper.GetString(SMTPUsernameConfigKey),
		viper.GetString(SMTPPasswordConfigKey),
	)

	return dialer
}
