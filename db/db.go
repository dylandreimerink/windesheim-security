package db

import (
	"github.com/jinzhu/gorm"
	_ "github.com/jinzhu/gorm/dialects/mysql" //Import for its side effects
	"github.com/pkg/errors"
	"github.com/sirupsen/logrus"
	"github.com/spf13/viper"
)

const (
	//MySQLConnectionStringConfigKey is the key where the mysql connection string list located in the config file
	MySQLConnectionStringConfigKey = "mysql.connection_string"
	//MySQLLogEnabledConfigKey is the key where the log enabled flag for the database connection is located in the config file
	MySQLLogEnabledConfigKey = "mysql.log_enabled"
	//
	MySQLMaxIdleConnConfigKey = "mysql.max_idle_connections"
	//
	MySQLMaxActiveConnConfigKey = "mysql.max_active_connections"
)

var (
	//The global variable which caches the database connecton
	conn *gorm.DB

	//A list of models which should be auto migrated
	registeredModels []interface{}
)

func init() {
	//Setting default config values
	viper.SetDefault(MySQLLogEnabledConfigKey, false)
	viper.SetDefault(MySQLMaxIdleConnConfigKey, 10)
	viper.SetDefault(MySQLMaxActiveConnConfigKey, 100)
}

//GetConnection returns a database connection
func GetConnection() (*gorm.DB, error) {
	//Check if we already have a connection
	if conn != nil {
		//Confirm the connection is still alive
		if err := conn.DB().Ping(); err != nil {
			return nil, errors.Wrap(err, "Error while pinging database")
		}

		return conn, nil
	}

	//Open a database connection using the configured connection string
	conn, err := gorm.Open("mysql", viper.GetString(MySQLConnectionStringConfigKey))
	if err != nil {
		return nil, errors.Wrap(err, "Error while opening DB connection")
	}

	//Configure the database connection pool
	conn.DB().SetMaxIdleConns(viper.GetInt(MySQLMaxIdleConnConfigKey))
	conn.DB().SetMaxOpenConns(viper.GetInt(MySQLMaxActiveConnConfigKey))

	//Configure the logmode
	conn.LogMode(viper.GetBool(MySQLLogEnabledConfigKey))

	//Set logrus as logger
	conn.SetLogger(&gormToLogrusLogger{})

	return conn, nil
}

//Implements the grom logger interface and passes logs to logrus
type gormToLogrusLogger struct{}

func (l *gormToLogrusLogger) Print(v ...interface{}) {
	logrus.Print(v...)
}

//AutoMigrate will migrate the database schema
func AutoMigrate() error {
	conn, err := GetConnection()
	if err != nil {
		return err
	}

	return conn.AutoMigrate(registeredModels...).Error
}
