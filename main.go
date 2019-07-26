package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"math/rand"
	"net/http"
	"reflect"
	"strconv"
	"strings"
	"time"

	"github.com/couchbase/gocb"
	"github.com/dgrijalva/jwt-go"
	"github.com/google/uuid"
	"github.com/gorilla/mux"
	"gopkg.in/couchbase/gocb.v1/cbft"
)

var (
	cbConnStr    = "couchbase://localhost"
	cbDataBucket = "travel-sample"
	cbUserBucket = "travel-users"
	cbUsername   = "Administrator"
	cbPassword   = "password"
	jwtSecret    = []byte("UNSECURE_SECRET_TOKEN")
)

var (
	ErrUserExists    = errors.New("user already exists")
	ErrUserNotFound  = errors.New("user does not exist")
	ErrBadPassword   = errors.New("password does not match")
	ErrBadAuthHeader = errors.New("bad authentication header format")
	ErrBadAuth       = errors.New("invalid auth token")
)

var globalCluster *gocb.Cluster
var globalBucket *gocb.Bucket
var globalCollection *gocb.Collection
var userBucket *gocb.Bucket
var userCollection *gocb.Collection
var flightCollection *gocb.Collection

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
	Name     string   `json:"name"`
	Password string   `json:"password"`
	Flights  []string `json:"flights"`
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
		authHeader = req.Header.Get("Authentication")
		authHeaderParts = strings.SplitN(authHeader, " ", 2)
		if authHeaderParts[0] != "Bearer" {
			writeJsonFailure(w, 400, ErrBadAuthHeader)
			return false
		}
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
	rows, err := globalCluster.Query(queryStr, nil)
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
	rows, err := globalCluster.Query(queryStr, nil)
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
	rows, err = globalCluster.Query(queryStr, nil)
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
	spec := gocb.LookupInSpec{}
	userKey := reqData.User
	passRes, err := userCollection.LookupIn(userKey, []gocb.LookupInOp{
		spec.Get("password", nil),
	}, nil)
	if gocb.IsKeyNotFoundError(err) {
		writeJsonFailure(w, 401, ErrUserNotFound)
		return
	} else if err != nil {
		fmt.Println(gocb.ErrorCause(err))
		writeJsonFailure(w, 500, err)
		return
	}

	var password string
	err = passRes.ContentAt(0, &password)
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

	userKey := reqData.User
	user := jsonUser{
		Name:     reqData.User,
		Password: reqData.Password,
		Flights:  nil,
	}
	_, err := userCollection.Insert(userKey, user, nil)
	if gocb.IsKeyExistsError(err) {
		writeJsonFailure(w, 409, ErrUserExists)
		return
	} else if err != nil {
		fmt.Println(reflect.TypeOf(err))
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

	userKey := authUser.Name

	var flightIDs []string
	spec := gocb.LookupInSpec{}
	res, err := userCollection.LookupIn(userKey, []gocb.LookupInOp{
		spec.Get("flights", nil),
	}, nil)
	if err != nil {
		writeJsonFailure(w, 500, err)
		return
	}

	res.ContentAt(0, &flightIDs)

	var flight jsonBookedFlight
	var flights []jsonBookedFlight
	for _, flightID := range flightIDs {
		res, err := flightCollection.Get(flightID, nil)
		if err != nil {
			writeJsonFailure(w, 500, err)
			return
		}
		res.Content(&flight)
		flights = append(flights, flight)
	}

	respData.Data = flights

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

	userKey := authUser.Name
	var user jsonUser
	res, err := userCollection.Get(userKey, nil)
	if err != nil {
		writeJsonFailure(w, 500, err)
		return
	}
	cas := res.Cas()
	res.Content(&user)

	for _, flight := range reqData.Flights {
		flight.BookedOn = time.Now().Format("01/02/2006")
		respData.Data.Added = append(respData.Data.Added, flight)
		flightID, err := uuid.NewRandom()
		if err != nil {
			writeJsonFailure(w, 500, err)
		}
		user.Flights = append(user.Flights, flightID.String())
		_, err = flightCollection.Upsert(flightID.String(), flight, nil)
		if err != nil {
			writeJsonFailure(w, 500, err)
		}
	}

	opts := gocb.ReplaceOptions{Cas: cas}
	_, err = userCollection.Replace(userKey, user, &opts)
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

	//qp := cbft.NewConjunctionQuery(cbft.NewTermQuery("hotel").Field("type"))
	qp := gocb.NewConjunctionQuery(gocb.NewTermQuery("hotel").Field("type"))

	if location != "" && location != "*" {
		qp.And(gocb.NewDisjunctionQuery(
			gocb.NewMatchPhraseQuery(location).Field("country"),
			gocb.NewMatchPhraseQuery(location).Field("city"),
			gocb.NewMatchPhraseQuery(location).Field("state"),
			gocb.NewMatchPhraseQuery(location).Field("address"),
		))
	}

	if description != "" && description != "*" {
		qp.And(cbft.NewDisjunctionQuery(
			cbft.NewMatchPhraseQuery(description).Field("description"),
			cbft.NewMatchPhraseQuery(description).Field("name"),
		))
	}

	q := gocb.SearchQuery{Name: "travel-search", Query: qp}
	results, err := globalCluster.SearchQuery(q, &gocb.SearchQueryOptions{Limit: 100})
	if err != nil {
		writeJsonFailure(w, 500, err)
		return
	}

	spec := gocb.LookupInSpec{}
	respData.Data = []jsonHotel{}
	var hit gocb.SearchResultHit
	for results.Next(&hit) {
		res, _ := globalCollection.LookupIn(hit.ID, []gocb.LookupInOp{
			spec.Get("country", nil),
			spec.Get("city", nil),
			spec.Get("state", nil),
			spec.Get("address", nil),
			spec.Get("name", nil),
			spec.Get("description", nil),
		}, nil)
		// We ignore errors here since some hotels are missing various
		//  pieces of data, but every key exists since it came from FTS.

		var hotel jsonHotel
		res.ContentAt(0, &hotel.Country)
		res.ContentAt(1, &hotel.City)
		res.ContentAt(2, &hotel.State)
		res.ContentAt(3, &hotel.Address)
		res.ContentAt(4, &hotel.Name)
		res.ContentAt(5, &hotel.Description)
		respData.Data = append(respData.Data, hotel)
	}

	encodeRespOrFail(w, respData)
}

func main() {
	var err error

	// Connect to Couchbase
	clusterOpts := gocb.ClusterOptions{
		Authenticator: gocb.PasswordAuthenticator{
			cbUsername,
			cbPassword,
		},
	}
	globalCluster, err = gocb.Connect(cbConnStr, clusterOpts)
	if err != nil {
		panic(err)
	}

	// Open the bucket
	globalBucket = globalCluster.Bucket(cbDataBucket, nil)
	userBucket = globalCluster.Bucket(cbUserBucket, nil)

	// Select the default collection
	globalCollection = globalBucket.DefaultCollection(nil)
	userCollection = userBucket.Collection("userData", "users", nil)
	flightCollection = userBucket.Collection("userData", "flights", nil)

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
