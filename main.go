/* ================================================================================================
	File Name : restapiserver.go
	Fucntion : This is the one of the Utility file of restapi service.
				The basic functionalities of this file are:
				start REST API server for web clients (browsers)
	Author : Venkat Masuldari
	Date : 18.12.2019
   ==================================================================================================== */

package main

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	_ "net/http/pprof"
	"os"
	"os/signal"
	"syscall"

	"github.com/ramstime/restapiservice/db"
	l4gconfig "github.com/ramstime/restapiservice/l4gconfig"
	l4g "github.com/jeanphorn/log4go" 
        //"code.google.com/p/log4go"

	//"errors"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/url"
	"strings"
	"time"

	intg "github.com/ramstime/restapiservice/restapiserver"

	oidc "github.com/coreos/go-oidc"
	"github.com/google/uuid"
	"github.com/gorilla/mux"
	"github.com/pkg/errors"
)

const (
	// OK SUCCESS status is success state
	OK = "OK"
	// FAILED status is failed state
	FAILED = "FAILED"
)

// ConfigDetails is the structure to read the l4g env variables.
type ConfigDetails struct {
	nbiRestListenerIpPort string
	keyCloakIPPort        string
	noLog                 string
	TLSFlag               string
	CallbackURI           string
}

//CompanyDetails is
type CompanyDetails struct {
	cfg ConfigDetails
}

//AppAccessToken will have token of
var AppAccessToken string

//client_id will have keycloak id
var clientID string

//NotifyRespChannel will store channel
var NotifyRespChannel = make(chan int)
var notifChannel = make(chan int)

//CompanyInfoMap will storing all comp details with compid as key
var CompanyInfoMap map[string]intg.CompanyInfo
var logdir = "/tmp/log/"
var logfile = "restserver"

const (
	noLog         = "noLog"
	restapiIPPort = "restapiIPPort"
	//TLSFlag will enable or disable tls
	TLSFlag        = "TLSFlag"
	keyCloakIPPort = "keyCloakIPPort"
	keyCloakurl    = "/auth/realms/master/protocol/openid-connect/token"
	configURL      = "/auth/realms/master"
	COMPTokenURL   = "/auth/realms/comp/protocol/openid-connect/token"

	COMPDelSubsURL = "/api/companyinfo/v1/comp_instance/{compid}"
	COMPANYAllURL  = "/api/companyinfo/v1/all"
	//http://127.0.0.1:9070/api/companyinfo/v1/company?compid=cisco - 323
	COMPANYPOSTURL = "/api/companyinfo/v1/comp_instance/{compid}" //{compid:[0-9]+}"
	COMPANYGETURL  = "/api/companyinfo/v1/comp_instance"          //{compid:[0-9]+}"
	COMPPatchURL   = "/api/companyinfo/v1/comp_instance/{compid}"
	CallbackURI    = "CallbackURI"
)

func (cfg *ConfigDetails) readConfig() {

	l4g.Info("starting readConfig... ")
	var flag bool
	cfg.nbiRestListenerIpPort, flag = os.LookupEnv(restapiIPPort)
	if flag == false {
		err := errors.New("env nbiRestListenerIpPort not found")
		l4g.Error(err, "failed reading nbiRestListenerIpPort setting it to localhost:9070")
		cfg.nbiRestListenerIpPort = "127.0.0.1:9070"
	}

	cfg.CallbackURI, flag = os.LookupEnv(CallbackURI)
	if flag == false {
		err := errors.New("env CallbackURI not found")
		l4g.Error(err, "failed reading CallbackURI setting it to localhost:7070")
		cfg.CallbackURI = "127.0.0.1:7070"
	}

	cfg.noLog, flag = os.LookupEnv(noLog)
	if flag == false {
		err := errors.New("env noLog not found")
		l4g.Error(err, "failed reading noLog")
		cfg.noLog = "true"
	}
	l4g.Info(" noLog: ", cfg.noLog)

	cfg.TLSFlag, flag = os.LookupEnv(TLSFlag)
	if flag == false {
		err := errors.New("env noTLSFlagLog not found")
		l4g.Error(err, "failed reading TLSFlag")
		cfg.TLSFlag = "false"
	}
	l4g.Info(" TLSFlag: ", cfg.TLSFlag)

}

// CreateMap - Create a genericmap in the redis db service
func (cmpinfo *CompanyDetails) CreateMap(MapObj interface{}, resourceName string) (err error) {

	l4g.Info("Trying to Create data: ", MapObj, " resourceName ", resourceName)

	// if len(MapObj) == 0 {
	// 	l4g.Info("map is Empty")

	// 	err = errors.New("map is Empty")
	// 	return
	// }

	var JSONData []byte
	JSONData, err = json.Marshal(MapObj)
	if err != nil {
		l4g.Error(err, "Error occured in Json Encoding")
		//	core.LogAlarm(core.JsonObj)

		return
	}
	l4g.Info("marshaling successful")
	l4g.Trace("JSON data = ", JSONData)
	err = db.UpdateKey(resourceName, string(JSONData))
	if err != nil {
		l4g.Error(err, "Failed to data")

		return
	}
	l4g.Info("stored successfully")

	return

}

// ReadMap - Read a map from the config service
func (cmpinfo *CompanyDetails) ReadMap(MapObj interface{}, ResourceName string) (err error) {

	l4g.Info("trying to read ResourceName:", ResourceName)
	ResourceRsp, err := db.Get(ResourceName)
	if ResourceRsp == "" || err != nil {
		l4g.Error(err, "Failed to Get ResourceName: ", ResourceName)
		return
	}
	err = json.Unmarshal([]byte(ResourceRsp), &MapObj)
	if err != nil {
		l4g.Error(err, "UnMarshal failed.")

		return
	}
	l4g.Info("Decode success ResourceName= ", ResourceName, "MapObj=", MapObj)

	return

}

//PostReq will
func PostReq(urlLink string, contentType string, jsonValue []byte) {

	l4g.Info("PostReq:", urlLink)

	l4g.Info("sending json data:", string(jsonValue))
	response, err := http.Post(urlLink, contentType, bytes.NewBuffer(jsonValue))
	if err != nil {
		l4g.Error(err, "The HTTP post subscription request failed with error: ")
	} else {

		l4g.Info("resp:", response)
		data, _ := ioutil.ReadAll(response.Body)
		l4g.Info("data: ", string(data))
	}
}

// generateUUID func will generate unique id.
func generateUUID() string {

	uid := uuid.New()
	l4g.Trace("UUID: ", uid)

	return uid.String()
}

//GetTLSKeyClient will
func (cmpinfo *CompanyDetails) GetTLSKeyClient() (client *http.Client) {

	//var client *http.Client
	l4g.Info("trying to create client")
	// Load client cert
	/*
		cert, err := tls.LoadX509KeyPair("certs/client.pem", "certs/client.key")
		if err != nil {
			l4g.Error(err,  "Loading cert failed ")
			return
		}
		// Load CA cert
		caCert, err := ioutil.ReadFile("certs/server.pem")
		if err != nil {
			l4g.Error(err,  "Reading cert failed ")
			return
		}
		caCertPool := x509.NewCertPool()
		caCertPool.AppendCertsFromPEM(caCert)
	*/
	tlsConfig := &tls.Config{
		//Certificates:       []tls.Certificate{cert},
		//RootCAs:            caCertPool,
		InsecureSkipVerify: true, //Enable this incase the certificate is invalid. example. certificate contains fqdn as CN but we are accessing using IP
	}
	tlsConfig.BuildNameToCertificate()
	transport := &http.Transport{TLSClientConfig: tlsConfig}
	client = &http.Client{Transport: transport, Timeout: 10 * time.Second}

	return
}

//GetTLSClient will provide the secure client for rest api
func (cmpinfo *CompanyDetails) GetTLSClient() (client *http.Client) {

	//var client *http.Client
	if cmpinfo.cfg.TLSFlag == "true" {
		l4g.Info("TLSFlag is true")
		// Load client cert

		cert, err := tls.LoadX509KeyPair("certs/client.pem", "certs/client.key")
		if err != nil {
			l4g.Error(err, "Loading cert failed ")
			return
		}
		// Load CA cert
		caCert, err := ioutil.ReadFile("certs/server.pem")
		if err != nil {
			l4g.Error(err, "Reading cert failed ")
			return
		}
		caCertPool := x509.NewCertPool()
		caCertPool.AppendCertsFromPEM(caCert)
		tlsConfig := &tls.Config{
			Certificates:       []tls.Certificate{cert},
			RootCAs:            caCertPool,
			InsecureSkipVerify: true, //Enable this incase the certificate is invalid. example. certificate contains fqdn as CN but we are accessing using IP
		}
		tlsConfig.BuildNameToCertificate()
		transport := &http.Transport{TLSClientConfig: tlsConfig}
		client = &http.Client{Transport: transport, Timeout: 10 * time.Second}
	} else {
		l4g.Info("TLSFlag is not true")
		client = &http.Client{Timeout: 10 * time.Second}
	}
	return
}

//ExtractToken will validate auth
func (cmpinfo *CompanyDetails) ExtractToken(w http.ResponseWriter, req *http.Request) (err error) {

	l4g.Info("req: ", req)
	if err = req.ParseForm(); err != nil {
		l4g.Error(err, "ParseForm failed")
		SendCustomErrResp("ParseForm failed"+" with err:"+err.Error(), http.StatusBadRequest, w)
		return
	}
	authToken := req.Header["Authorization"]
	//authToken := req.Header["Authorization"][0]
	if len(authToken) <= 0 {
		err = errors.New("Header must contain authorization")
		l4g.Error(err, "Header validation failed, it must contain auth")
		SendCustomErrResp("Header must contain authorization", http.StatusBadRequest, w)
		return
	}
	//strings.Split("a,b,c", ","))
	authList := strings.Split(authToken[0], " ")
	if len(authList) < 2 {
		//err.Text = "Header parsing failed for authorization"
		err = errors.New("Header must contain bearer authorization")
		l4g.Error(err, "Header parsing failed for authorization")
		SendCustomErrResp("Header parsing failed for authorization", http.StatusBadRequest, w)
		return
	}
	if strings.EqualFold("bearer", authList[0]) != true {
		err = errors.New("Header must contain bearer authorization")
		l4g.Error(err, "Header validation failed for authorization")
		SendCustomErrResp("Header must contain bearer authorization", http.StatusBadRequest, w)
		return
	}
	token := authList[1]
	if token == "" {
		err = errors.New("token is empty")
		l4g.Error(err, "token is invalid ")
		SendCustomErrResp("Token is empty", http.StatusBadRequest, w)
		return
	}
	client := cmpinfo.GetTLSKeyClient()
	err = cmpinfo.VerifyToken(client, cmpinfo.cfg.keyCloakIPPort, token, clientID)
	if err != nil {
		l4g.Error(err, "token verification Failed ")
		SendCustomErrResp("Token verification failed"+" with err:"+err.Error(), http.StatusUnauthorized, w)
		return
	}
	l4g.Info("valid req")

	return
}

//VerifyToken will validate if the token is from right client or not
func (cmpinfo *CompanyDetails) VerifyToken(client *http.Client, configURL string, AccessToken string, clientID string) (err error) {

	ctx := context.Background()
	newctx := oidc.ClientContext(ctx, client)
	provider, err := oidc.NewProvider(newctx, configURL)
	if err != nil {
		l4g.Error(err, "Failed getting provider for configURL:", configURL)
		return
	}
	oidcConfig := &oidc.Config{
		ClientID: clientID,
	}
	verifier := provider.Verifier(oidcConfig)
	//l4g.Trace( "AccessToken : ", AccessToken)
	l4g.Info("AccessToken : ", AccessToken)
	l4g.Info("clientId : ", clientID)
	l4g.Info("configURL : ", configURL)
	//idToken, err := verifier.Verify(newctx, result["access_token"].(string))
	_, err = verifier.Verify(newctx, AccessToken)
	if err != nil {
		l4g.Error(err, "Access token verification failed")
		return
	}
	l4g.Info("Successfully verified access token")
	return
}

//ValidateTokenReq will validate
func (cmpinfo *CompanyDetails) ValidateTokenReq(req intg.GetTokenReq, w http.ResponseWriter) (err error) {

	l4g.Info("req : ", req)
	if req.GrantType == "" {
		err = errors.New("GrantType is empty")
		l4g.Error(err, "GrantType is empty ", req)
		http.Error(w, http.StatusText(http.StatusBadRequest), http.StatusBadRequest)
		return
	}
	if strings.ToLower(req.GrantType) != "password" && strings.ToLower(req.GrantType) != "client_credentials" {
		err = errors.New("invalid GrantType")
		l4g.Error(err, "grantType must be password or client_credentials ", req)
		http.Error(w, http.StatusText(http.StatusBadRequest), http.StatusBadRequest)
		return
	}
	if strings.ToLower(req.GrantType) == "client_credentials" {
		if req.ClientID == "" || req.ClientSecret == "" {
			err = errors.New("empty credentials")
			l4g.Error(err, "ClientID or ClientSecret is empty ", req)
			http.Error(w, http.StatusText(http.StatusBadRequest), http.StatusBadRequest)
			return
		}
	}
	if strings.ToLower(req.GrantType) == "password" {
		if req.Username == "" || req.Password == "" {
			err = errors.New("empty user details")
			l4g.Error(err, "Username or Password is empty ", req)
			//w.WriteHeader(204) // send the headers with a 204 response code.
			http.Error(w, http.StatusText(http.StatusBadRequest), http.StatusBadRequest)
			return
		}
	}
	l4g.Info("valid req : ", req)

	return
}

//GetToken will
func (cmpinfo *CompanyDetails) GetToken(req intg.GetTokenReq, urlLink string) (getTokenResp intg.GetTokenResp, err error) {

	urlVal := url.Values{}

	//urlVal.Set("username", "admin")
	//urlVal.Set("password", "Admin123!")

	urlVal.Set("username", req.Username)
	urlVal.Set("password", req.Password)
	urlVal.Set("client_id", req.ClientID)
	//urlVal.Set("client_id", "admin-cli")

	urlVal.Set("client_secret", req.ClientSecret)
	urlVal.Set("grant_type", req.GrantType)
	//urlVal.Set("grant_type", "client_credentials")
	client := cmpinfo.GetTLSKeyClient()
	l4g.Info("Trying to Get token from keyCloak: ", urlLink)
	l4g.Info("urlVal : ", urlVal)

	response, err := client.PostForm(urlLink, urlVal)
	if err != nil {
		l4g.Error(err, "Token request failed")
		return
	}
	l4g.Info("Got token resp from keyCloak ", urlLink)
	l4g.Trace("Got token resp : ", response)
	//for {
	err = json.NewDecoder(response.Body).Decode(&getTokenResp)
	if err != nil { //&& err != io.EOF {
		l4g.Error(err, "Decode failed for token resp getTokenResp:", getTokenResp)
		return
	}
	//}
	if getTokenResp.AccessToken == "" {
		err = errors.New("accesstoken is empty")
		l4g.Error(err, "token is empty getTokenResp:", getTokenResp)
		return
	}
	l4g.Trace("Got token from keyCloak getTokenResp:", getTokenResp)
	return
}

//SendCustomErrResp will
func SendCustomErrResp(detailErr string, code int, w http.ResponseWriter) {

	http.Error(w, http.StatusText(code), code)
	var subsErrResp intg.SubscriptionErrResp
	subsErrResp.Status = code
	subsErrResp.Detail = detailErr
	w.Header().Set("Content-Type", "application/json")
	l4g.Info("Sending subsErrResp :  \n", subsErrResp)
	err := json.NewEncoder(w).Encode(subsErrResp)
	if err != nil {
		l4g.Error(err, "The json encodingg failed subsErrResp:", subsErrResp)
		return
	}
	l4g.Info("Sending resp :  \n", w)

	return
}

//SendErrResp will
func SendErrResp(subsErrResp intg.SubscriptionErrResp, w http.ResponseWriter) {

	w.Header().Set("Content-Type", "application/json")
	l4g.Info("Sending subsErrResp :  \n", subsErrResp)
	err := json.NewEncoder(w).Encode(subsErrResp)
	if err != nil {
		l4g.Error(err, "The json encodingg failed subsErrResp:", subsErrResp)
		return
	}

}

//GetStringInBetween will
func GetStringInBetween(str string, start string, end string) (result string) {

	l4g.Info(" str: %s  len:", str, len(str))
	l4g.Info(" start: %s  end: %s", start, end)
	s := strings.Index(str, start)
	l4g.Info(" start s: ", s)
	if s == -1 {
		err := errors.New("start str not found")
		l4g.Error(err, "start str not found")
		return
	}
	s += len(start)
	l4g.Info(" moved s: ", s)
	e := strings.Index(str, end)
	l4g.Info(" e: ", e)
	if e == -1 || s > e {
		err := errors.New("end str not found")
		l4g.Error(err, "end str not found")
		return
	}
	l4g.Info(" e: ", e)
	l4g.Info(" extracted str: %s", str[s:e])
	return str[s:e]
}

func (cmpinfo *CompanyDetails) postNotificationToExtApp(compinfo intg.CompanyInfo, subsID string) (err error) {

	//l4g.Info( "resp: ", resp)
	//jsonData := map[string]string{"firstname": "Nic", "lastname": "Raboy"}
	var jsonValue []byte
	jsonValue, err = json.Marshal(compinfo)
	if err != nil {
		l4g.Error(err, "The json parsing failed with error")
		return
	}
	req, err := http.NewRequest("POST", CallbackURI+"/subsapp/v1/notifications", bytes.NewBuffer(jsonValue))
	if err != nil {
		l4g.Error(err, "http NewRequest failed")
		return
	}
	req.Header.Set("Content-Type", "application/json")
	client := cmpinfo.GetTLSClient()
	l4g.Info("Trying to send Notification req:  ", req)
	resp, err := client.Do(req)
	if err != nil {
		l4g.Error(err, "The notification request failed with error")
		return
	}
	defer resp.Body.Close()
	l4g.Info("got resp: ", resp)
	//data, _ := ioutil.ReadAll(resp.Body)
	//l4g.Info( "data: ", string(data))
	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusNoContent {
		err = errors.New(resp.Status)
		l4g.Error(err, "The notification response returned error")
		return
	}
	l4g.Info("sucessfull resp")
	return
}

//GetTokenfromKeyCloak will
func (cmpinfo *CompanyDetails) GetTokenfromKeyCloak(w http.ResponseWriter, r *http.Request) {
	// Get the token from keyCloak and return
	l4g.Info("got req: ", r)
	//w.Write([]byte("this is a key endpoint"))
	err := r.ParseForm()
	if err != nil {
		l4g.Error(err, "ParseForm failed")
		fmt.Fprintf(w, "ParseForm() err: ", err)
		return
	}
	var tokenReq intg.GetTokenReq
	tokenReq.Username = r.FormValue("username")
	tokenReq.Password = r.FormValue("password")
	tokenReq.ClientID = r.FormValue("client_id")
	tokenReq.ClientSecret = r.FormValue("client_secret")
	tokenReq.GrantType = r.FormValue("grant_type")
	tokenEndPoint := cmpinfo.cfg.keyCloakIPPort + keyCloakurl
	tokenReq.TokenEndPoint = tokenEndPoint
	l4g.Info("tokenReq:  \n", tokenReq)
	err = cmpinfo.ValidateTokenReq(tokenReq, w)
	if err != nil {
		l4g.Error(err, "tokenReq validation failed tokenReq:  ", tokenReq)
		//w.WriteHeader(204) // send the headers with a 204 response code.
		return
	}
	getTokenResp, err := cmpinfo.GetToken(tokenReq, tokenEndPoint)
	if err != nil {
		l4g.Error(err, "Gettoken req failed for tokenReq:  and tokenEndPoint:", tokenReq, tokenEndPoint)
		//w.WriteHeader(204) // send the headers with a 204 response code.
		http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
		return
	}
	l4g.Trace("Decode success getTokenResp:  \n", getTokenResp)
	client := cmpinfo.GetTLSKeyClient()
	AppAccessToken = getTokenResp.AccessToken //result["access_token"].(string)
	clientID = tokenReq.ClientID
	lconfigURL := cmpinfo.cfg.keyCloakIPPort + configURL
	err = cmpinfo.VerifyToken(client, lconfigURL, getTokenResp.AccessToken, tokenReq.ClientID)
	if err != nil {
		l4g.Error(err, "token is invalid ")
		//http.Error(w, http.StatusText(http.StatusBadRequest), http.StatusBadRequest)
		//return
	}
	w.Header().Set("Content-Type", "application/json")
	err = json.NewEncoder(w).Encode(getTokenResp)
	if err != nil {
		l4g.Error(err, "The json encodingg failed with error")
		//w.WriteHeader(203) // send the headers with a 204 response code.
		http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
		return
	}
	l4g.Info("Resp:  \n", w)

	//w.Write([]byte("<HTML><HEAD> <TITLE>Your Title Here</TITLE>	</HEAD>	</HTML> "))

}

//DeleteCompanyDetails will del
func (cmpinfo *CompanyDetails) DeleteCompanyDetails(w http.ResponseWriter, req *http.Request) {

	l4g.Info("req ", req)
	vars := mux.Vars(req)
	compID := vars["compid"]
	l4g.Info("Got request for compID: ", compID)
	err := cmpinfo.ExtractToken(w, req)
	if err != nil {
		l4g.Error(err, "ExtractToken failed")
		return
	}
	if len(CompanyInfoMap) == 0 {
		l4g.Warn("No entries found")
		SendCustomErrResp("No subscscription found ", http.StatusNotFound, w)
		return
	}
	//compinfo := make([]intg.CompanyInfo, 0)
	var compinfo intg.CompanyInfo
	var ok bool
	compinfo, ok = CompanyInfoMap[compID]
	if !ok {
		err := errors.New("no entries found")
		l4g.Error(err, "No entry found for this compID:%s", compID)
		detailErr := "No entry found for compID: " + compID
		SendCustomErrResp(detailErr, http.StatusNotFound, w)
		return
	}
	l4g.Info("Deleting compID: ", compID, "compinfo: ", compinfo)

	delete(CompanyInfoMap, compID)
	err = cmpinfo.CreateMap(CompanyInfoMap, "CompanyInfoMap")
	if err != nil {
		l4g.Error(err, "storing CompanyInfoMap failed ")
		detailErr := "storing subs failed subsID: " + compID
		SendCustomErrResp(detailErr, http.StatusInternalServerError, w)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	err = json.NewEncoder(w).Encode(compinfo)
	if err != nil {
		l4g.Error(err, "The json encodingg failed with error")
		SendCustomErrResp(" subsResp encoding failed", http.StatusInternalServerError, w)
		return
	}
	l4g.Info("Resp:  \n", w)

}

func (cmpinfo *CompanyDetails) triggerNotif() {

	for {
		l4g.Info("waiting for post trigger ...")
		<-notifChannel
		l4g.Info("start triggering integrate ...")
		if len(CompanyInfoMap) <= 0 {
			err := errors.New("no subsriptions found")
			l4g.Error(err, "no subsriptions found")
			return
		}
		var compinfo []intg.CompanyInfo
		for compID, comp := range CompanyInfoMap {
			l4g.Info("got subsID: ", compID)
			l4g.Info("got compinfo: ", comp)
			compinfo = append(compinfo, comp)
			l4g.Info("Posting Notificaiton:  \n", compinfo[0].ID)
			cmpinfo.postNotificationToExtApp(comp, comp.ID)
		}
		l4g.Info("finished triggering .")
	}
}

//GetAllCompDetails comments todo
func (cmpinfo *CompanyDetails) GetAllCompDetails(w http.ResponseWriter, r *http.Request) {
	// Get all the fields

	l4g.Info("got request:  ", r.Body)
	l4g.Info("Get request for all comp ")
	/*
			jsonData := map[string]string{"firstname": "Nic", "lastname": "Raboy"}

			jsonValue, err := json.Marshal(jsonData)
			if err != nil {
				l4g.Error(err,  "The json parsing failed with error")
				return
			}
				w.Write([]byte("This is a GetAllCompDetails"))
		w.Write([]byte(jsonValue))

	*/
	// err := cmpinfo.ExtractToken(w, r)
	// if err != nil {
	// 	l4g.Error(err, "ExtractToken failed")
	// 	return
	// }

	w.Header().Set("Content-Type", "application/json")
	if len(CompanyInfoMap) == 0 {
		l4g.Warn("No entries found")
		SendCustomErrResp("No comp found in server", http.StatusNotFound, w)
		return
	}
	var compinfo []intg.CompanyInfo
	for compID, comp := range CompanyInfoMap {
		l4g.Info("adding compID: ", compID)
		l4g.Info("adding comp: ", comp)
		compinfo = append(compinfo, comp)
	}

	err := json.NewEncoder(w).Encode(compinfo)
	if err != nil {
		l4g.Error(err, "The json encodingg failed with error")
		SendCustomErrResp("compinfo encoding failed", http.StatusInternalServerError, w)
		return
	}

	l4g.Info("sending resp: ", w)

}

//GetCompDetails comments todo
func (cmpinfo *CompanyDetails) GetCompDetails(w http.ResponseWriter, r *http.Request) {

	l4g.Info("got request:  ", r)
	vars := mux.Vars(r)

	//compid := vars["compid"]

	query := r.URL.Query()
	compid := query.Get("compid")

	// err := cmpinfo.ExtractToken(w, r)
	// if err != nil {
	// 	l4g.Error(err,  "ExtractToken failed")
	// 	return
	// }
	w.Header().Set("Content-Type", "application/json")
	l4g.Info("Get request for vars: ", vars)
	l4g.Info("Get request from compid: ", compid)
	compinfo, ok := CompanyInfoMap[compid]
	if !ok {
		err := errors.New("no content")
		l4g.Error(err, "no entry found for ", compid)
		SendCustomErrResp("entry not found for compid: "+compid, http.StatusNotFound, w)
		return
	}
	l4g.Info("Found entry for compid: ", compid, "compinfo: ", compinfo)
	err := json.NewEncoder(w).Encode(compinfo)
	if err != nil {
		l4g.Error(err, "The json encodingg failed with error")
		SendCustomErrResp("compinfo encoding failed ", http.StatusInternalServerError, w)
		return
	}
	l4g.Info("sending resp: ", w)

}

//CreateCompanyDetails will map the resp
func (cmpinfo *CompanyDetails) CreateCompanyDetails(w http.ResponseWriter, r *http.Request) {

	l4g.Info("got request:  ", r)

	vars := mux.Vars(r)
	compid := vars["compid"]

	// err := cmpinfo.ExtractToken(w, r)
	// if err != nil {
	// 	l4g.Error(err, "ExtractToken failed")
	// 	return
	// }
	w.Header().Set("Content-Type", "application/json")
	l4g.Info("Get request from compid: ", compid)
	_, ok := CompanyInfoMap[compid]
	if !ok {
		err := errors.New("no content")
		l4g.Error(err, "no entry found for ", compid)
		//SendCustomErrResp("ID not found  compid: "+compid, http.StatusNotFound, w)
		//return
	}

	decoder := json.NewDecoder(r.Body)
	var compinfo intg.CompanyInfo
	//for {
	err := decoder.Decode(&compinfo)
	if err != nil {
		l4g.Error(err, "Unmarshal failed")
		SendCustomErrResp("compinfo Unmarshal failed", http.StatusBadRequest, w)
		return
	}
	l4g.Info("Decode success subsReq:", compinfo)

	CompanyInfoMap[compid] = compinfo
	err = cmpinfo.CreateMap(CompanyInfoMap, "CompanyInfoMap")
	if err != nil {
		l4g.Error(err, "storing notifResp failed ")
		SendCustomErrResp("storing CompanyInfoMap failed ", http.StatusInternalServerError, w)
		return
	}
	w.WriteHeader(200) // send the headers with a 200 response code.
	result := 1

	notifChannel <- result
	l4g.Info("CreateCompanyDetails success for compid:  ", compid)
	l4g.Info("sending resp :  ", w)

}

//UpdateCompanyDetails will map the resp
func (cmpinfo *CompanyDetails) UpdateCompanyDetails(w http.ResponseWriter, r *http.Request) {

	l4g.Info("got request:  ", r)

	vars := mux.Vars(r)
	compid := vars["compid"]

	// err := cmpinfo.ExtractToken(w, r)
	// if err != nil {
	// 	l4g.Error(err, "ExtractToken failed")
	// 	return
	// }
	w.Header().Set("Content-Type", "application/json")
	l4g.Info("Get request from compid: ", compid)
	_, ok := CompanyInfoMap[compid]
	if !ok {
		err := errors.New("no content")
		l4g.Error(err, "no entry found for ", compid)
		SendCustomErrResp("ID not found  compid: "+compid, http.StatusNotFound, w)
		return
	}

	decoder := json.NewDecoder(r.Body)
	var compinfo intg.CompanyInfo
	//for {
	err := decoder.Decode(&compinfo)
	if err != nil {
		l4g.Error(err, "Unmarshal failed")
		SendCustomErrResp("compinfo Unmarshal failed", http.StatusBadRequest, w)
		return
	}
	l4g.Info("Decode success compinfo:", compinfo)

	CompanyInfoMap[compid] = compinfo
	err = cmpinfo.CreateMap(CompanyInfoMap, "CompanyInfoMap")
	if err != nil {
		l4g.Error(err, "storing compinfo failed ")
		SendCustomErrResp("storing CompanyInfoMap failed ", http.StatusInternalServerError, w)
		return
	}
	w.WriteHeader(200) // send the headers with a 200 response code.
	//result = 1
	//NotifyRespChannel <- result
	l4g.Info("UpdateCompanyDetails success for compid:  ", compid)
	l4g.Info("sending resp :  ", w)

}

func (cmpinfo *CompanyDetails) handleroot(w http.ResponseWriter, r *http.Request) {

	l4g.Info("got request:  ", r)
	w.WriteHeader(200) // send the headers with a 200 response code.

}
func (cmpinfo *CompanyDetails) handleRequests(myRouter *mux.Router) {

	l4g.Info("routing...")
	//myRouter := mux.NewRouter().StrictSlash(true)
	myRouter.HandleFunc(COMPTokenURL, cmpinfo.GetTokenfromKeyCloak).Methods("GET", "POST")

	myRouter.HandleFunc(COMPDelSubsURL, cmpinfo.DeleteCompanyDetails).Methods("DELETE")

	myRouter.HandleFunc(COMPANYPOSTURL, cmpinfo.CreateCompanyDetails).Methods("POST", "PUT")

	myRouter.HandleFunc(COMPANYGETURL, cmpinfo.GetCompDetails).Methods("GET")
	//myRouter.HandleFunc(COMPANYURL, cmpinfo.GetCompDetails).
	//Queries("compid", "{compid:[0-9]+}").Methods("GET")

	myRouter.HandleFunc(COMPANYAllURL, cmpinfo.GetAllCompDetails).Methods("GET")
	//myRouter.HandleFunc(COMPANYAllURL, cmpinfo.GetAllCompDetails).
	//	Queries("fields", "{all_fields}").Methods("GET")
	myRouter.HandleFunc(COMPPatchURL, cmpinfo.UpdateCompanyDetails).Methods("PATCH")

	//http.HandleFunc("/home", cmpinfo.handleroot)
	//listenAddress := ":" + strconv.Itoa(nbiRestListenerPort)
	http.Handle("/", myRouter)

	//http.ListenAndServe(nbiRestListenerPort, myRouter)

}

/*
//split method used to find the mentioned character
func split(r rune) bool {
	return r == '/' || r == '[' || r == ']'
}
*/

func initLog() error {
	var err error
	logPath := l4gconfig.InitLogging(logfile, logdir)
	if logPath != "" {
		fmt.Println("Logs are captured in " + logPath)
	} else {
		fmt.Println("Error starting logs")
		err = errors.New("Error starting logs")
	}
	return err
}

func (cmpinfo *CompanyDetails) loaddata() {

	var compinfo intg.CompanyInfo

	compinfo.Name = "google"
	compinfo.Revenue = "200 billions"
	compinfo.TotalEmp = 30000
	compinfo.ID = "google - " + generateUUID()
	compinfo.Branches = []string{"india", "america", "germany"}
	var Emp = intg.Employee{}
	var Person = intg.Person{}

	Person.Name = "ramakrishna"
	Person.Spouse = "kajol"
	Person.Dob = "13 may 1991"
	Person.ID = "Driving license"
	Person.Nationality = "india"

	Emp.EmpID = "908123"
	Emp.Salary = "2 millions"
	Emp.Department = "R&D"
	Emp.Products = []string{"flight booking", "5g nodes", "e-commerse website"}
	Emp.Revenue = "45 billions"
	Emp.Technology = []string{"kubernetes", "Machine Learning", "BigData", "telecom", "Banking"}
	Emp.Programming = []string{"c++", "golang", "python"}
	Emp.Laptop = "dell"
	Emp.Gender = "male"
	Emp.Address = "banglore local"
	Emp.Team = "Gladiators"
	Emp.Leaves = "20"
	Emp.Hobbies = []string{"cricket", "programming", "football", "technology", "movies"}

	Person.Emp = Emp

	Person1 := Person
	Person1.Name = "vijay"
	Person1.Spouse = "soujanya"

	compinfo.Employees = []intg.Person{Person, Person1}
	//compinfo.Employees[0].Emp = intg.Employee{}

	CompanyInfoMap[compinfo.ID] = compinfo
	err := cmpinfo.CreateMap(CompanyInfoMap, "CompanyInfoMap")
	if err != nil {
		l4g.Error(err, "storing CompanyInfoMap failed ")
		return
	}

	l4g.Info("CompanyInfoMap : ", CompanyInfoMap)

}

// type Author struct {
// 	Name    string `json:"name"`
// 	Age     int    `json:"age"`
// 	Company string `json:"Company"`
// 	Books   string `json:"Books"`
// }

func main() {
	if errlog := initLog(); errlog != nil {
		os.Exit(1)
	}
	go func() {
		fmt.Println(http.ListenAndServe("localhost:6060", nil))
	}()

	l4g.Info("starting main... ")
	var cmpinfo = CompanyDetails{}
	cmpinfo.cfg.readConfig()

	CompanyInfoMap = make(map[string]intg.CompanyInfo)

	// json, err := json.Marshal(Author{Name: "Elliot", Age: 25, Company: "google", Books: "technology stack"})
	// if err != nil {
	// 	fmt.Println(err)
	// }
	//db.UpdateKey("ramakrishna", string(json))

	//db.Get("ramakrishna")

	//cmpinfo.loaddata()
	err := cmpinfo.ReadMap(&CompanyInfoMap, "CompanyInfoMap")

	retryCount := 0
	for err != nil {
		if retryCount > 4 {
			break
		}
		l4g.Error(err, "Reading CompanyInfoMap failed ")
		retryCount++
		time.Sleep(2 * time.Second)
		l4g.Info("Retrying Read of CompanyInfoMap retryCount:", retryCount)
		err = cmpinfo.ReadMap(&CompanyInfoMap, "CompanyInfoMap")
	}
	if len(CompanyInfoMap) > 0 {
		l4g.Info("CompanyInfoMap : ", CompanyInfoMap)
	}

	//r := mux.NewRouter()
	r := mux.NewRouter().StrictSlash(true)

	// Start Rest Server in another thread
	cmpinfo.handleRequests(r)

	cfg := &tls.Config{
		MinVersion:               tls.VersionTLS12,
		CurvePreferences:         []tls.CurveID{tls.CurveP521, tls.CurveP384, tls.CurveP256},
		PreferServerCipherSuites: true,
		//InsecureSkipVerify:       false,
		/*CipherSuites: []uint16{
			tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA,
			tls.TLS_RSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_RSA_WITH_AES_256_CBC_SHA,
			tls.TLS_RSA_WITH_AES_128_GCM_SHA256,
		},*/
	}

	srv := &http.Server{
		Addr: cmpinfo.cfg.nbiRestListenerIpPort,
		// Good practice to set timeouts to avoid Slowloris attacks.
		WriteTimeout: time.Second * 15,
		ReadTimeout:  time.Second * 15,
		IdleTimeout:  time.Second * 60,
		Handler:      r, // Pass our instance of gorilla/mux in.
		TLSConfig:    cfg,
	}

	go func() {

		l4g.Info(" RESTAPI Server Listening on " + cmpinfo.cfg.nbiRestListenerIpPort)
		if cmpinfo.cfg.TLSFlag != "true" {
			l4g.Info("TLS disabled")
			if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
				l4g.Error(err, "failed to ListenAndServe")
				for err != nil {
					time.Sleep(2 * time.Second)
					l4g.Info("RESTAPI Server Listening on " + cmpinfo.cfg.nbiRestListenerIpPort)
					if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {

						l4g.Error(err, "failed to ListenAndServe")
					}
				}
			}
		} else {
			l4g.Info("TLS Enabled")
			err := srv.ListenAndServeTLS("certs/server.pem", "certs/server.key")
			if err != nil {
				l4g.Error(err, "ListenAndServeTLS err:")
				for err != nil {
					time.Sleep(2 * time.Second)
					l4g.Info("RESTAPI Server Listening on " + cmpinfo.cfg.nbiRestListenerIpPort)
					err := srv.ListenAndServeTLS("certs/server.pem", "certs/server.key")
					if err != nil {
						l4g.Error(err, "ListenAndServeTLS err:")
					}
				}

			}
		}
		l4g.Info("exiting REST server")

	}()

	go cmpinfo.triggerNotif()

	stop := make(chan os.Signal, 1)
	// We'll accept graceful shutdowns when quit via SIGINT (Ctrl+C)
	// SIGKILL, SIGQUIT or SIGTERM (Ctrl+/) will not be caught.
	signal.Notify(stop, os.Interrupt)
	signal.Notify(stop, syscall.SIGINT)
	signal.Notify(stop, syscall.SIGKILL)
	l4g.Info("waiting for interupt...")
	// Block until we receive our signal.
	interupt := <-stop

	l4g.Info("got interupt: ", interupt)

	// Create a deadline to wait for.
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	// Doesn't block if no connections, but will otherwise wait
	// until the timeout deadline.
	//srv.Shutdown(ctx)
	if err := srv.Shutdown(ctx); err != nil {
		l4g.Error(err, "failed to shutdown")
	}
	// Optionally, you could run srv.Shutdown in a goroutine and block on
	// <-ctx.Done() if your application should wait for other services
	// to finalize based on context cancellation.

	l4g.Info("shuting down")
	os.Exit(0)

}
