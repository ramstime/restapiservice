package restapiserver

import "time"

const (
	Grpc_IP       = "0.0.0.0"
	Grpc_PORT     = "8888"
	Grpc_PROTOCOL = "tcp"
)

type SubscriptionErrResp struct {
	Status int    `json:"status"`
	Detail string `json:"detail"`
	Title  string `json:"title"`
}

type SubscriptionResp struct {
	Filter        string `json:"filter"`
	CallbackURI   string `json:"callbackUri"`
	LcnAPIVersion string `json:"lcnApiVersion"`
	ID            string `json:"id"`
}

//SubscriptionRespToken will
type SubscriptionRespToken struct {
	SubsResp      SubscriptionResp
	TokenReq      GetTokenReq
	CallbackURI   string
	TokenEndPoint string
}

// NotificationReq will be sent from integration service to Ntcapp (netact)
type NotificationReq struct {
	VnfInstanceID    string    `json:"vnfInstanceId"`
	Operation        string    `json:"operation"`
	TimeStamp        time.Time `json:"timeStamp"`
	NotificationType string    `json:"notificationType"`
	OperationState   string    `json:"operationState"`
	SubscriptionID   string    `json:"subscriptionId"`
	ID               string    `json:"id"`
}

type Metadata struct {
	IntegrationStatus  string        `json:"integrationStatus"`
	IntegrationDetails []CompanyInfo `json:"integrationDetails"`
}
type NotificationResp struct {
	Metadata Metadata `json:"metadata"`
}

//GetTokenReq will store request details
type GetTokenReq struct {
	Username      string
	Password      string
	ClientID      string
	ClientSecret  string
	GrantType     string
	TokenEndPoint string
}

//GetTokenResp
type GetTokenResp struct {
	AccessToken      string `json:"access_token"`
	ExpiresIn        int    `json:"expires_in"`
	RefreshExpiresIn int    `json:"refresh_expires_in"`
	RefreshToken     string `json:"refresh_token"`
	TokenType        string `json:"token_type"`
	NotBeforePolicy  int    `json:"not-before-policy"`
	SessionState     string `json:"session_state"`
	Scope            string `json:"scope"`
}

//Employee is
type Employee struct {
	EmpID       string   `json:"empid"`
	EmailID     string   `json:"emmailid"`
	Salary      string   `json:"salary"`
	Department  string   `json:"Department"`
	Products    []string `json:"products"`
	Revenue     string   `json:"revenue"`
	Technology  []string `json:"technology"`
	Programming []string `json:"programming"`
	Laptop      string   `json:"laptop"`
	Gender      string   `json:"gender"`
	Address     string   `json:"address"`
	Team        string   `json:"team"`
	Leaves      string   `json:"leaves"`
	Hobbies     []string `json:"hobbies"`
}

//Person will
type Person struct {
	Name        string   `json:"name"`
	Spouse      string   `json:"spouse"`
	Dob         string   `json:"Dob"`
	Emp         Employee `json:"Employee"`
	ID          string   `json:"id"`
	Nationality string   `json:"nationality"`
}

//CompanyInfo is
type CompanyInfo struct {
	Employees []Person `json:"employees"`
	Name      string   `json:"Name"`
	Revenue   string   `json:"revenue"`
	TotalEmp  int      `json:"totalemp"`
	Branches  []string `json:"branches"`
	ID        string   `json:"ID"`
}
