package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"github.com/couchbase/gocb"
	"github.com/couchbase/gocb/cbft"
	"github.com/dgrijalva/jwt-go"
	"github.com/gorilla/mux"
	"math"
	"math/rand"
	"net/http"
	"strconv"
	"strings"
	"time"
)

var (
	cbConnStr  = "couchbase://localhost"
	cbBucket   = "travel-sample"
	cbPassword = ""
	jwtSecret  = []byte("UNSECURE_SECRET_TOKEN")
)

var (
	ErrUserExists    = errors.New("user already exists")
	ErrUserNotFound  = errors.New("user does not exist")
	ErrBadPassword   = errors.New("password does not match")
	ErrBadAuthHeader = errors.New("bad authentication header format")
	ErrBadAuth       = errors.New("invalid auth token")
)

var globalCluster *gocb.Cluster = nil
var globalBucket *gocb.Bucket = nil

type jsonBookedFlight struct {
	Name               string  `json:"name"`
	Flight             string  `json:"flight"`
	Price              float64 `json:"price"`
	Date               string  `json:"date"`
	SourceAirport      string  `json:"sourceairport"`
	DestinationAirport string  `json:"destinationairport"`
	BookedOn           string  `json:"bookedon"`
}

type jsonUser struct {
	Name     string             `json:"name"`
	Password string             `json:"password"`
	Flights  []jsonBookedFlight `json:"flights"`
}

type jsonFlight struct {
	Name               string  `json:"name"`
	Flight             string  `json:"flight"`
	Equipment          string  `json:"equipment"`
	Utc                string  `json:"utc"`
	SourceAirport      string  `json:"sourceairport"`
	DestinationAirport string  `json:"destinationairport"`
	Price              float64 `json:"price"`
	FlightTime         int     `json:"flighttime"`
}

type jsonAirport struct {
	AirportName string `json:"airportname"`
}

type jsonHotel struct {
	Country     string `json:"country"`
	City        string `json:"city"`
	State       string `json:"state"`
	Address     string `json:"address"`
	Name        string `json:"name"`
	Description string `json:"description"`
}

type jsonContext []string

func (c *jsonContext) Add(msg string) {
	*c = append(*c, msg)
}

type jsonFailure struct {
	Failure string `json:"failure"`
}

func writeJsonFailure(w http.ResponseWriter, code int, err error) {
	failObj := jsonFailure{
		Failure: err.Error(),
	}

	failBytes, err := json.Marshal(failObj)
	if err != nil {
		panic(err)
	}

	w.WriteHeader(code)
	w.Write(failBytes)
}

func decodeReqOrFail(w http.ResponseWriter, req *http.Request, data interface{}) bool {
	err := json.NewDecoder(req.Body).Decode(data)
	if err != nil {
		writeJsonFailure(w, 500, err)
		return false
	}
	return true
}

func encodeRespOrFail(w http.ResponseWriter, data interface{}) {
	err := json.NewEncoder(w).Encode(data)
	if err != nil {
		writeJsonFailure(w, 500, err)
	}
}

func createJwtToken(user string) (string, error) {
	return jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"user": user,
	}).SignedString(jwtSecret)
}

type AuthedUser struct {
	Name string
}

func decodeAuthUserOrFail(w http.ResponseWriter, req *http.Request, user *AuthedUser) bool {
	authHeader := req.Header.Get("Authorization")
	authHeaderParts := strings.SplitN(authHeader, " ", 2)
	if authHeaderParts[0] != "Bearer" {
		writeJsonFailure(w, 400, ErrBadAuthHeader)
		return false
	}

	authToken := authHeaderParts[1]
	token, err := jwt.Parse(authToken, func(token *jwt.Token) (interface{}, error) {
		// Don't forget to validate the alg is what you expect:
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("Unexpected signing method: %v", token.Header["alg"])
		}

		return jwtSecret, nil
	})
	if err != nil {
		writeJsonFailure(w, 400, ErrBadAuthHeader)
		return false
	}

	authUser := token.Claims.(jwt.MapClaims)["user"].(string)
	if authUser == "" {
		writeJsonFailure(w, 400, ErrBadAuth)
		return false
	}

	user.Name = authUser

	return true
}

// GET /api/airports?search=xxx
type jsonAirportSearchResp struct {
	Data    []jsonAirport `json:"data"`
	Context jsonContext   `json:"context"`
}

func AirportSearch(w http.ResponseWriter, req *http.Request) {
	var respData jsonAirportSearchResp

	searchKey := req.FormValue("search")

	var queryStr string
	if len(searchKey) == 3 {
		queryStr = fmt.Sprintf("SELECT airportname FROM `travel-sample` WHERE faa='%s'", strings.ToUpper(searchKey))
	} else if len(searchKey) == 4 && searchKey == strings.ToUpper(searchKey) {
		queryStr = fmt.Sprintf("SELECT airportname FROM `travel-sample` WHERE icao ='%s'", searchKey)
	} else {
		queryStr = fmt.Sprintf("SELECT airportname FROM `travel-sample` WHERE airportname like '%s%%'", searchKey)
	}

	respData.Context.Add(queryStr)
	q := gocb.NewN1qlQuery(queryStr)
	rows, err := globalBucket.ExecuteN1qlQuery(q, nil)
	if err != nil {
		writeJsonFailure(w, 500, err)
		return
	}

	respData.Data = []jsonAirport{}
	var airport jsonAirport
	for rows.Next(&airport) {
		respData.Data = append(respData.Data, airport)
		airport = jsonAirport{}
	}

	encodeRespOrFail(w, respData)
}

// GET /api/flightPaths/{from}/{to}?leave=mm/dd/YYYY
type jsonFlightSearchResp struct {
	Data    []jsonFlight `json:"data"`
	Context jsonContext  `json:"context"`
}

func FlightSearch(w http.ResponseWriter, req *http.Request) {
	var respData jsonFlightSearchResp

	reqVars := mux.Vars(req)
	leaveDate, err := time.Parse("01/02/2006", req.FormValue("leave"))
	if err != nil {
		writeJsonFailure(w, 500, err)
		return
	}

	fromAirport := reqVars["from"]
	toAirport := reqVars["to"]
	dayOfWeek := int(leaveDate.Weekday())

	var queryStr string
	queryStr =
		"SELECT faa FROM `travel-sample` WHERE airportname='" + fromAirport + "'" +
			" UNION" +
			" SELECT faa FROM `travel-sample` WHERE airportname='" + toAirport + "'"

	respData.Context.Add(queryStr)
	q := gocb.NewN1qlQuery(queryStr)
	rows, err := globalBucket.ExecuteN1qlQuery(q, nil)
	if err != nil {
		writeJsonFailure(w, 500, err)
		return
	}

	var fromAirportFaa string
	var toAirportFaa string

	var airportInfo struct {
		Faa string `json:"faa"`
	}
	rows.Next(&airportInfo)
	fromAirportFaa = airportInfo.Faa
	rows.Next(&airportInfo)
	toAirportFaa = airportInfo.Faa

	err = rows.Close()
	if err != nil {
		writeJsonFailure(w, 500, err)
		return
	}

	queryStr =
		"SELECT a.name, s.flight, s.utc, r.sourceairport, r.destinationairport, r.equipment" +
			" FROM `travel-sample` AS r" +
			" UNNEST r.schedule AS s" +
			" JOIN `travel-sample` AS a ON KEYS r.airlineid" +
			" WHERE r.sourceairport = '" + toAirportFaa + "'" +
			" AND r.destinationairport = '" + fromAirportFaa + "'" +
			" AND s.day=" + strconv.Itoa(dayOfWeek) +
			" ORDER BY a.name ASC;"

	respData.Context.Add(queryStr)
	q = gocb.NewN1qlQuery(queryStr)
	rows, err = globalBucket.ExecuteN1qlQuery(q, nil)
	if err != nil {
		writeJsonFailure(w, 500, err)
		return
	}

	respData.Data = []jsonFlight{}
	var flight jsonFlight
	for rows.Next(&flight) {
		flight.FlightTime = int(math.Ceil(rand.Float64() * 8000))
		flight.Price = math.Ceil(float64(flight.FlightTime)/8*100) / 100
		respData.Data = append(respData.Data, flight)
		flight = jsonFlight{}
	}

	encodeRespOrFail(w, respData)
}

// POST /api/user/login
type jsonUserLoginReq struct {
	User     string `json:"user"`
	Password string `json:"password"`
}

type jsonUserLoginResp struct {
	Data struct {
		Token string `json:"token"`
	} `json:"data"`
	Context jsonContext `json:"context"`
}

func UserLogin(w http.ResponseWriter, req *http.Request) {
	var respData jsonUserLoginResp
	var reqData jsonUserLoginReq
	if !decodeReqOrFail(w, req, &reqData) {
		return
	}

	userKey := fmt.Sprintf("user::%s", reqData.User)
	passRes, err := globalBucket.LookupIn(userKey).Get("password").Execute()
	if err == gocb.ErrKeyExists {
		writeJsonFailure(w, 401, ErrUserNotFound)
		return
	} else if err != nil {
		writeJsonFailure(w, 500, err)
		return
	}

	var password string
	err = passRes.Content("password", &password)
	if err != nil {
		writeJsonFailure(w, 500, err)
		return
	}

	if password != reqData.Password {
		writeJsonFailure(w, 401, ErrBadPassword)
		return
	}

	token, err := createJwtToken(reqData.User)
	if err != nil {
		writeJsonFailure(w, 500, err)
		return
	}

	respData.Data.Token = token

	encodeRespOrFail(w, respData)
}

//POST /api/user/signup
type jsonUserSignupReq struct {
	User     string `json:"user"`
	Password string `json:"password"`
}

type jsonUserSignupResp struct {
	Data struct {
		Token string `json:"token"`
	} `json:"data"`
	Context jsonContext `json:"context"`
}

func UserSignup(w http.ResponseWriter, req *http.Request) {
	var respData jsonUserSignupResp
	var reqData jsonUserSignupReq
	if !decodeReqOrFail(w, req, &reqData) {
		return
	}

	userKey := fmt.Sprintf("user::%s", reqData.User)
	user := jsonUser{
		Name:     reqData.User,
		Password: reqData.Password,
		Flights:  nil,
	}
	_, err := globalBucket.Insert(userKey, user, 0)
	if err == gocb.ErrKeyExists {
		writeJsonFailure(w, 409, ErrUserExists)
		return
	} else if err != nil {
		writeJsonFailure(w, 500, err)
		return
	}

	token, err := createJwtToken(user.Name)
	if err != nil {
		writeJsonFailure(w, 500, err)
		return
	}

	respData.Data.Token = token

	encodeRespOrFail(w, respData)
}

// GET /api/user/{username}/flights
type jsonUserFlightsResp struct {
	Data    []jsonBookedFlight `json:"data"`
	Context jsonContext        `json:"context"`
}

func UserFlights(w http.ResponseWriter, req *http.Request) {
	var respData jsonUserFlightsResp
	var authUser AuthedUser

	if !decodeAuthUserOrFail(w, req, &authUser) {
		return
	}

	userKey := fmt.Sprintf("user::%s", authUser.Name)
	var user jsonUser
	_, err := globalBucket.Get(userKey, &user)
	if err != nil {
		writeJsonFailure(w, 500, err)
		return
	}

	respData.Data = user.Flights

	encodeRespOrFail(w, respData)
}

//POST  /api/user/{username}/flights
type jsonUserBookFlightReq struct {
	Flights []jsonBookedFlight `json:"flights"`
}

type jsonUserBookFlightResp struct {
	Data struct {
		Added []jsonBookedFlight `json:"added"`
	} `json:"data"`
	Context jsonContext `json:"context"`
}

func UserBookFlight(w http.ResponseWriter, req *http.Request) {
	var respData jsonUserBookFlightResp
	var reqData jsonUserBookFlightReq
	var authUser AuthedUser

	if !decodeAuthUserOrFail(w, req, &authUser) {
		return
	}

	if !decodeReqOrFail(w, req, &reqData) {
		return
	}

	userKey := fmt.Sprintf("user::%s", authUser.Name)
	var user jsonUser
	cas, err := globalBucket.Get(userKey, &user)
	if err != nil {
		writeJsonFailure(w, 500, err)
		return
	}

	for _, flight := range reqData.Flights {
		flight.BookedOn = time.Now().Format("01/02/2006")
		respData.Data.Added = append(respData.Data.Added, flight)
		user.Flights = append(user.Flights, flight)
	}

	_, err = globalBucket.Replace(userKey, user, cas, 0)
	if err != nil {
		// We intentionally do not handle CAS mismatch, as if the users
		//  account was already modified, they probably want to know.
		writeJsonFailure(w, 500, err)
		return
	}

	encodeRespOrFail(w, respData)
}

// GET /api/hotel/{description}/{location}
type jsonHotelSearchResp struct {
	Data    []jsonHotel `json:"data"`
	Context jsonContext `json:"context"`
}

func HotelSearch(w http.ResponseWriter, req *http.Request) {
	var respData jsonHotelSearchResp

	reqVars := mux.Vars(req)
	description := reqVars["description"]
	location := reqVars["location"]

	qp := cbft.NewConjunctionQuery(cbft.NewTermQuery("hotel").Field("type"))

	if location != "" && location != "*" {
		qp.And(cbft.NewDisjunctionQuery(
			cbft.NewMatchPhraseQuery(location).Field("country"),
			cbft.NewMatchPhraseQuery(location).Field("city"),
			cbft.NewMatchPhraseQuery(location).Field("state"),
			cbft.NewMatchPhraseQuery(location).Field("address"),
		))
	}

	if description != "" && description != "*" {
		qp.And(cbft.NewDisjunctionQuery(
			cbft.NewMatchPhraseQuery(description).Field("description"),
			cbft.NewMatchPhraseQuery(description).Field("name"),
		))
	}

	q := gocb.NewSearchQuery("travel-search", qp).
		Limit(100)
	rows, err := globalBucket.ExecuteSearchQuery(q)
	if err != nil {
		writeJsonFailure(w, 500, err)
		return
	}

	respData.Data = []jsonHotel{}
	for _, hit := range rows.Hits() {
		res, _ := globalBucket.LookupIn(hit.Id).
			Get("country").
			Get("city").
			Get("state").
			Get("address").
			Get("name").
			Get("description").
			Execute()
		// We ignore errors here since some hotels are missing various
		//  pieces of data, but every key exists since it came from FTS.

		var hotel jsonHotel
		res.Content("country", &hotel.Country)
		res.Content("city", &hotel.City)
		res.Content("state", &hotel.State)
		res.Content("address", &hotel.Address)
		res.Content("name", &hotel.Name)
		res.Content("description", &hotel.Description)
		respData.Data = append(respData.Data, hotel)
	}

	encodeRespOrFail(w, respData)
}

func main() {
	var err error

	// Connect to Couchbase
	globalCluster, err = gocb.Connect(cbConnStr)
	if err != nil {
		panic(err)
	}

	// Authenticate to the cluster using RBAC (Couchbase Server 5.0+)
	globalCluster.Authenticate(gocb.PasswordAuthenticator{
		"Administrator",
		"password",
	})

	// Open the bucket
	globalBucket, err = globalCluster.OpenBucket(cbBucket, cbPassword)
	if err != nil {
		panic(err)
	}

	// Create a router for our server
	r := mux.NewRouter()

	// Set up our REST endpoints
	r.Path("/api/airports").Methods("GET").HandlerFunc(AirportSearch)
	r.Path("/api/flightPaths/{from}/{to}").Methods("GET").HandlerFunc(FlightSearch)
	r.Path("/api/user/login").Methods("POST").HandlerFunc(UserLogin)
	r.Path("/api/user/signup").Methods("POST").HandlerFunc(UserSignup)
	r.Path("/api/user/{username}/flights").Methods("GET").HandlerFunc(UserFlights)
	r.Path("/api/user/{username}/flights").Methods("POST").HandlerFunc(UserBookFlight)
	r.Path("/api/hotel/{description}/").Methods("GET").HandlerFunc(HotelSearch)
	r.Path("/api/hotel/{description}/{location}/").Methods("GET").HandlerFunc(HotelSearch)

	// Serve our public files out of root
	r.PathPrefix("/").Handler(http.FileServer(http.Dir("./public")))

	// Set up our routing
	http.Handle("/", r)

	// Listen on port 8080
	http.ListenAndServe(":8080", nil)
}
