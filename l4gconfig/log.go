package l4gconfig

import (
	"bytes"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	l4g "code.google.com/p/log4go"

	"github.com/gorilla/mux"
)

const regEx = "[A-Za-z0-9-_]+"

var LOG_TMP = "/tmp/"

func InitLogging(fileName, dir string) string {
	if dir == "" {
		dir = "/opt/log"
	}
	fmt.Println("App name :" + filepath.Base(fileName) + " Dir :" + dir)
	configPath, logPath, err := createTempLogSetting(filepath.Base(fileName), dir)
	if err == nil {
		l4g.LoadConfiguration(configPath)
		return logPath
	}
	return ""
}

func createTempLogSetting(appname, dir string) (string, string, error) {

	logSettingFileName := filepath.Clean(LOG_TMP + appname + "_logging.xml")
	logFileName := filepath.Clean(dir + "/" + appname + ".log")
	errMakeDir := os.MkdirAll(filepath.Clean(dir), os.ModePerm)
	if errMakeDir != nil {
		fmt.Println("error creating log directories :" + errMakeDir.Error())
		return "", "", errMakeDir
	}

	fd, err := os.Create(logSettingFileName)
	if err != nil {
		fmt.Println("error creating log setting xml file " + err.Error())
		return "", "", err
	}
	defer fd.Close()
	var (
		loglevel     string
		logfilecount string
		logmaxsize   string
	)

	if os.Getenv("L4GLEVEL") != "" {
		loglevel = os.Getenv("L4GLEVEL")
	} else {
		loglevel = "ERROR"
	}

	if os.Getenv("L4GMAXSIZE") != "" {
		logmaxsize = os.Getenv("L4GMAXSIZE")
	} else {
		logmaxsize = "10M"
	}

	if os.Getenv("L4GCOUNT") != "" {
		logfilecount = os.Getenv("L4GCOUNT")
	} else {
		logfilecount = "30"
	}

	setting := `<logging>
<filter enabled="true">
<tag>file</tag>
<type>file</type>
<level>` + loglevel + `</level>
<property name="filename">` + logFileName + `</property>
<property name="format">[%D %T] [%L] (%S) %M</property>
<property name="rotate">true</property>
<property name="maxsize">` + logmaxsize + `</property>
<property name="filecount">` + logfilecount + `</property>
</filter>
</logging>`
	_, err = fd.WriteString(setting)
	if err != nil {
		fmt.Println("error writing to log setting file")
		return "", "", err
	}
	return logSettingFileName, logFileName, err
}

// Handles set and get requests for loglevels.
func handleLogLevel(reqName string) http.HandlerFunc {
	hfunc := func(w http.ResponseWriter, r *http.Request) {
		input := getVars(r)
		lvl, err := l4g.GetLevel("file")
		l4g.Info(input)
		l4g.Info(lvl, err)
		if err != nil {
			fmt.Fprintf(w, "Error: %v\n", err)
			return
		}
		fmt.Println("req: " + reqName)
		if strings.EqualFold(reqName, "Get") {
			fmt.Fprintf(w, lvl+"\n")
		} else if strings.EqualFold(reqName, "Set") {
			if strings.EqualFold(lvl, input["Level"]) {
				fmt.Fprintf(w, "Error: Current Level is same as Requested Log Level.\n")
				return
			}
			err := l4g.SetLevel("file", input["Level"])
			if err != nil {
				fmt.Fprintf(w, "Error: %v\n", err)
				return
			} else {
				fmt.Fprintf(w, "Log Level changed from "+lvl+" to "+input["Level"]+"\n")
			}
		}
		l4g.Info("This is a test INFO Log")
		l4g.Debug("This is a test DEBUG Log")
	}
	return hfunc
}

//StartloglevelChangeListener starts a logchange  listener for dynamic log level change
func StartloglevelChangeListener() {
	//Dynamic loglevel change
	router := mux.NewRouter()
	router.HandleFunc("/getloglevel", handleLogLevel("Get"))
	router.HandleFunc("/setloglevel/{Level:"+regEx+"}", handleLogLevel("Set"))
	l4gport := os.Getenv("L4GPORT")
	if l4gport == "" {
		l4gport = "1234" //default port
	}
	srv := &http.Server{
		Handler: router,
		Addr:    "127.0.0.1:" + l4gport,
		// Good practice: enforce timeouts for servers you create!
		WriteTimeout: 15 * time.Second,
		ReadTimeout:  15 * time.Second,
	}
	srv.ListenAndServe()

}

func getVars(r *http.Request) map[string]string {
	vars := mux.Vars(r)
	r.ParseForm()
	if len(r.Form) != 0 {
		for k, v := range r.Form {
			vars[k] = v[0]
		}
	} else {
		l4g.Debug("No form elements in request")
	}
	// Method
	vars["Method"] = r.Method
	// Body
	buf := new(bytes.Buffer)
	buf.ReadFrom(r.Body)
	reqInBytes := buf.Bytes()
	vars["Body"] = string(reqInBytes)
	vars["Source"] = r.Header.Get("Source")
	vars["ClientName"] = r.Header.Get("ClientName")
	return vars
}
