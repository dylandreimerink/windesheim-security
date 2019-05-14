package main

import (
	"fmt"
	"net"
	"net/http"
	"os"

	"github.com/dylandreimerink/windesheim-security/db"
	"github.com/dylandreimerink/windesheim-security/handlers"
	"github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

const (
	listeningDomainNameConfigKey = "http.domainname"
	listeningPortConfigKey       = "http.port"
)

var servecmd = &cobra.Command{
	Use:   "winappoint",
	Short: "Winappoint is a web service in which you can store your appointments securely",
	RunE:  serveWinappoint,
}

var (
	cfgFile string
)

func init() {
	cobra.OnInitialize(initConfig)
	flags := servecmd.PersistentFlags()
	flags.StringVarP(&cfgFile, "config", "c", "", "Config file path (default is $PWD/.config.yaml)")

	flags.String("mysql-connection-string", "", "Set the mysql connection string")
	viper.BindPFlag(db.MySQLConnectionStringConfigKey, flags.Lookup("mysql-connection-string"))

	flags.String("domain-name", "localhost", "The domain name on which the HTTP server will listen (default is localhost)")
	viper.BindPFlag(listeningDomainNameConfigKey, flags.Lookup("domain-name"))

	flags.Int("http-port", 0, "The port HTTP requests will be served on")
	viper.BindPFlag(listeningPortConfigKey, flags.Lookup("http-port"))

	//Log the file and line number where the log was made
	logrus.StandardLogger().ReportCaller = true
}

func main() {
	//Execute the cli
	if err := servecmd.Execute(); err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
}

func initConfig() {
	// Don't forget to read config either from cfgFile or from pwd directory!
	if cfgFile != "" {
		// Use config file from the flag.
		viper.SetConfigFile(cfgFile)
	} else {
		pwd, err := os.Getwd()
		if err != nil {
			logrus.WithError(err).Fatal("Error while getting working directory")
		}

		// Search config in pwd with name ".config" (without extension).
		viper.AddConfigPath(pwd)
		viper.SetConfigName(".config")
	}

	if err := viper.ReadInConfig(); err != nil {
		logrus.WithError(err).Fatal("Can't read config")
	}
}

func serveWinappoint(cmd *cobra.Command, args []string) error {

	//Auto migrate the database
	err := db.AutoMigrate()
	if err != nil {
		return err
	}

	//Run all migrations the auto migrate can't do
	err = db.ManualMigrateDatabase()
	if err != nil {
		return err
	}


	listenAddr := fmt.Sprintf("%s:%d", viper.GetString(listeningDomainNameConfigKey), viper.GetInt(listeningPortConfigKey))

	listener, err := net.Listen("tcp", listenAddr)
	if err != nil {
		return err
	}

	logrus.Printf("Listening for HTTP connections on: http://%s", listener.Addr())

	//Create a new HTTP server
	server := http.Server{
		//Register the router from the handlers package
		Handler: handlers.RootRouter,
	}

	//Listen for HTTP connections
	err = server.Serve(listener)
	if err != nil && err != http.ErrServerClosed {
		return err
	}

	return nil
}
