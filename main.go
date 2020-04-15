package main

import (
	"crypto/tls"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"os"
	"strconv"

	"github.com/dylandreimerink/windesheim-security/db"
	"github.com/dylandreimerink/windesheim-security/handlers"
	"github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

const (
	listeningDomainNameConfigKey = "http.domainname"
	listeningPortConfigKey       = "http.port"

	listeningTLSPortConfigKey = "http.tls.port"
	TLSCertConfigKey          = "http.tls.cert_path"
	TLSKeyConfigKey           = "http.tls.key_path"
	TLSEnabledConfigKey       = "http.tls.enabled"
	HTTPRedirectConfigKey     = "http.tls.redirect_http"
)

var servecmd = &cobra.Command{
	Use:   "winnote",
	Short: "Winnote is a web service in which you can store your appointments securely",
	RunE:  serveWinnote,
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

	//Log the file and line number where the log was made
	logrus.SetReportCaller(true)

	//Strip the caller from the info logs since it is only interesting for error or debug logs
	logrus.AddHook(&callerStripperHook{
		levels: []logrus.Level{
			logrus.InfoLevel,
		},
	})

	level, err := logrus.ParseLevel(viper.GetString("logging.level"))
	if err != nil {
		logrus.WithError(err).Fatal("Invalid log level in config")
	}

	logrus.SetLevel(level)

	switch viper.GetString("logging.to") {
	case "stdout":
		logrus.SetOutput(os.Stdout)
	case "file":
		//Open a file, create it if it doesn't exist yet with permissions 0644 and append to the end if it already exists
		file, err := os.OpenFile(viper.GetString("logging.file_path"), os.O_RDWR|os.O_CREATE|os.O_APPEND, 0644)
		if err != nil {
			logrus.WithError(err).Fatal("Can't open log file")
		}

		logrus.SetOutput(file)
	default:
		logrus.Panicf("Invalid log destination: '%s'", viper.GetString("logging.to"))
	}
}

func serveWinnote(cmd *cobra.Command, args []string) error {

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

	errChan := make(chan error)

	if viper.GetBool(TLSEnabledConfigKey) {
		tlsListenAddr := fmt.Sprintf("%s:%d", viper.GetString(listeningDomainNameConfigKey), viper.GetInt(listeningTLSPortConfigKey))

		cert, err := tls.LoadX509KeyPair(viper.GetString(TLSCertConfigKey), viper.GetString(TLSKeyConfigKey))
		if err != nil {
			return err
		}

		tlsConfig := &tls.Config{

			//Add our cert to the list of certs we can serve
			Certificates: []tls.Certificate{
				cert,
			},
			//Currently only TLS v1.2 and v1.3 are regarded as secure
			MinVersion: tls.VersionTLS12,

			PreferServerCipherSuites: true,

			//Only use "strong" cipher suites
			CurvePreferences: []tls.CurveID{tls.CurveP521, tls.CurveP384, tls.CurveP256},
			CipherSuites: []uint16{
				tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
				tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
				tls.TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA,
				tls.TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA,
			},
		}

		tlsListener, err := tls.Listen("tcp", tlsListenAddr, tlsConfig)
		if err != nil {
			return err
		}

		logrus.Printf("Listening for HTTPS connections on: https://%s", tlsListener.Addr())

		//Create a new HTTPS server
		server := http.Server{
			//Register the router from the handlers package
			Handler: handlers.RootRouter,
		}

		go func() { errChan <- server.Serve(tlsListener) }()
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

	//If TLS and HTTP redirect is enabled, redirect all HTTP traffic to TLS
	if viper.GetBool(TLSEnabledConfigKey) && viper.GetBool(HTTPRedirectConfigKey) {
		server.Handler = http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
			url := &url.URL{
				Scheme: "https",
				Host:   net.JoinHostPort(viper.GetString(listeningDomainNameConfigKey), strconv.Itoa(viper.GetInt(listeningTLSPortConfigKey))),
				Path:   req.URL.Path,
			}
			http.Redirect(w, req, url.String(), http.StatusPermanentRedirect)
		})
	}

	//Listen for HTTP connections
	go func() { errChan <- server.Serve(listener) }()

	return <-errChan
}

type callerStripperHook struct {
	levels []logrus.Level
}

func (cs *callerStripperHook) Levels() []logrus.Level {
	return cs.levels
}

func (cs *callerStripperHook) Fire(entity *logrus.Entry) error {
	entity.Caller = nil
	return nil
}
