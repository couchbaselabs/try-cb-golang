package main

import (
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"github.com/couchbase/gocb/v2"
	"github.com/couchbase/gocb/v2/search"
	"github.com/dgrijalva/jwt-go"
	"github.com/google/uuid"
	"github.com/gorilla/handlers"
	"github.com/gorilla/mux"
	"github.com/sirupsen/logrus"
	"math"
	"math/rand"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"time"
)

var (
	defaultCBHost          = "db"
	defaultCBScheme        = "couchbases://" // Set to couchbase:// if using Couchbase Server Community Edition
	travelSampleBucketName = "travel-sample"
	defaultCBUsername      = "Administrator"
	defaultCBPassword      = "password"
	jwtSecret              = []byte("IAMSOSECRETIVE!")
)

var (
	ErrUserExists       = errors.New("user already exists")
	ErrUserNotFound     = errors.New("user does not exist")
	ErrUsernameNotMatch = errors.New("username does not match token")
	ErrBadPassword      = errors.New("password does not match")
	ErrBadAuthHeader    = errors.New("bad authentication header format")
	ErrBadAuth          = errors.New("invalid auth token")
)

type TravelSampleApp struct {
	cluster *gocb.Cluster
	bucket  *gocb.Bucket
	logger  *logrus.Logger
}

func writeJsonFailureWithContext(w http.ResponseWriter, code int, err error, context []string) {
	failObj := jsonFailure{
		Message: err.Error(),
	}
	if len(context) > 0 {
		failObj.Context = context
	}

	failBytes, err := json.Marshal(failObj)
	if err != nil {
		panic(err)
	}

	w.WriteHeader(code)
	w.Write(failBytes)
}

func writeJsonFailure(w http.ResponseWriter, code int, err error) {
	writeJsonFailureWithContext(w, code, err, nil)
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

type authedUser struct {
	Name string
}

func decodeAuthUserOrFail(w http.ResponseWriter, req *http.Request, user *authedUser) bool {
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
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
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

// AirportSearch performs a N1QL query lookup on an airport name or code.
// GET /api/airports?search=xxx
func (app *TravelSampleApp) AirportSearch(w http.ResponseWriter, req *http.Request) {
	searchKey := req.FormValue("search")
	queryParams := make([]interface{}, 1)

	queryStr := "SELECT airportname FROM `travel-sample`.`inventory`.`airport`"
	if len(searchKey) == 3 {
		// FAA code
		queryParams[0] = strings.ToUpper(searchKey)
		queryStr = fmt.Sprintf("%s WHERE faa=$1", queryStr)
	} else if len(searchKey) == 4 && (strings.ToUpper(searchKey) == searchKey || strings.ToLower(searchKey) == searchKey) {
		// ICAO code
		queryParams[0] = strings.ToUpper(searchKey)
		queryStr = fmt.Sprintf("%s WHERE icao=$1", queryStr)
	} else {
		// Airport name
		queryParams[0] = "%" + strings.ToLower(searchKey) + "%"
		queryStr = fmt.Sprintf("%s WHERE LOWER(airportname) LIKE $1", queryStr)
	}

	var respData jsonAirportSearchResp
	respData.Context.Add(fmt.Sprintf("N1QL query - scoped to inventory: %s", queryStr))
	rows, err := app.cluster.Query(queryStr, &gocb.QueryOptions{PositionalParameters: queryParams})
	if err != nil {
		app.logger.Printf("Failed to execute airport search query: %s", err)
		writeJsonFailure(w, 500, err)
		return
	}

	respData.Data = []jsonAirport{}
	for rows.Next() {
		var airport jsonAirport
		if err = rows.Row(&airport); err != nil {
			app.logger.Printf("Error occurred during airport search result parsing: %s", err)
			writeJsonFailure(w, 500, err)
			return
		}

		respData.Data = append(respData.Data, airport)
	}

	// We should always check for any errors that may have occurred on the stream.
	if err = rows.Err(); err != nil {
		app.logger.Printf("Error occurred during airport search result streaming: %s", err)
		writeJsonFailure(w, 500, err)
		return
	}

	encodeRespOrFail(w, respData)
}

// FlightSearch performs two N1Ql queries:
//    the first query finds the airport faa codes for the two airport names given
//    the second query finds the flights available between the two airport codes for the data provided
// GET /api/flightPaths/{from}/{to}?leave=mm/dd/YYYY
func (app *TravelSampleApp) FlightSearch(w http.ResponseWriter, req *http.Request) {
	leaveDate, err := time.Parse("01/02/2006", req.FormValue("leave"))
	if err != nil {
		app.logger.Printf("Failed to parse leave date: %s", err)
		writeJsonFailure(w, 500, err)
		return
	}

	// Find aiport faa code for source and destination airports
	reqVars := mux.Vars(req)
	queryParams := make(map[string]interface{}, 2)
	queryParams["fromAirport"] = reqVars["from"]
	queryParams["toAirport"] = reqVars["to"]
	faaQueryStr :=
		"SELECT faa AS fromFaa FROM `travel-sample`.`inventory`.`airport`" +
			" WHERE airportname=$fromAirport" +
			" UNION" +
			" SELECT faa AS toFaa FROM `travel-sample`.`inventory`.`airport`" +
			" WHERE airportname=$toAirport;"

	rows, err := app.cluster.Query(faaQueryStr, &gocb.QueryOptions{NamedParameters: queryParams})
	if err != nil {
		app.logger.Printf("Failed to execute flight search query: %s", err)
		writeJsonFailure(w, 500, err)
		return
	}

	var fromFaa string
	var toFaa string
	for rows.Next() {
		var airportInfo struct {
			FromFaa string `json:"fromFaa"`
			ToFaa   string `json:"toFaa"`
		}

		if err = rows.Row(&airportInfo); err != nil {
			app.logger.Printf("Error occurred during flight search result parsing: %s", err)
			writeJsonFailure(w, 500, err)
			return
		}

		if airportInfo.ToFaa != "" {
			toFaa = airportInfo.ToFaa
		}
		if airportInfo.FromFaa != "" {
			fromFaa = airportInfo.FromFaa
		}
	}
	if toFaa == "" || fromFaa == "" {
		writeJsonFailureWithContext(w, 404, errors.New("one of the specified airports is invalid"),
			[]string{faaQueryStr})
		return
	}

	// We should always check for any errors that may have occurred on the stream.
	if err = rows.Err(); err != nil {
		app.logger.Printf("Error occurred during flight search result streaming: %s", err)
		writeJsonFailure(w, 500, err)
		return
	}

	// Search for flights
	queryParams = make(map[string]interface{}, 3)
	queryParams["fromFaa"] = fromFaa
	queryParams["toFaa"] = toFaa
	queryParams["dayOfWeek"] = int(leaveDate.Weekday())
	queryStr :=
		"SELECT a.name, s.flight, s.utc, r.sourceairport, r.destinationairport, r.equipment" +
			" FROM `travel-sample`.`inventory`.`route` AS r" +
			" UNNEST r.schedule AS s" +
			" JOIN `travel-sample`.`inventory`.`airline` AS a ON KEYS r.airlineid" +
			" WHERE r.sourceairport=$fromFaa" +
			" AND r.destinationairport=$toFaa" +
			" AND s.day=$dayOfWeek" +
			" ORDER BY a.name ASC;"

	var respData jsonFlightSearchResp
	respData.Context.Add(faaQueryStr)
	respData.Context.Add(queryStr)
	rows, err = app.cluster.Query(queryStr, &gocb.QueryOptions{NamedParameters: queryParams})
	if err != nil {
		app.logger.Printf("Failed to execute flight search query: %s", err)
		writeJsonFailure(w, 500, err)
		return
	}

	for rows.Next() {
		var flight jsonFlight
		if err = rows.Row(&flight); err != nil {
			writeJsonFailure(w, 500, err)
			return
		}

		flight.FlightTime = int(math.Ceil(rand.Float64() * 8000))
		flight.Price = math.Ceil((float64(flight.FlightTime)/8)*100) / 100
		respData.Data = append(respData.Data, flight)
	}

	if len(respData.Data) == 0 {
		writeJsonFailureWithContext(w, 404, errors.New("no flights exist between these airports"),
			[]string{faaQueryStr, queryStr})
		return
	}

	// We should always check for any errors that may have occurred on the stream.
	if err = rows.Err(); err != nil {
		app.logger.Printf("Error occurred during flight search result streaming: %s", err)
		writeJsonFailure(w, 500, err)
		return
	}

	encodeRespOrFail(w, respData)
}

// UserLogin performs a KV lookup to try find the password for the provided username, ensuring that the user exists
// and that the password matches the password provided. It then creates and returns a JWT authentication token.
// POST /api/tenants/{tenant}/user/login
func (app *TravelSampleApp) UserLogin(w http.ResponseWriter, req *http.Request) {
	var reqData jsonUserLoginReq
	if !decodeReqOrFail(w, req, &reqData) {
		return
	}

	reqUser := strings.ToLower(reqData.User)
	reqPass := reqData.Password

	vars := mux.Vars(req)
	tenant := strings.ToLower(vars["tenant"])
	scope := app.bucket.Scope(tenant)
	users := scope.Collection("users")

	result, err := users.LookupIn(reqUser, []gocb.LookupInSpec{
		gocb.GetSpec("password", nil),
	}, nil)
	if errors.Is(err, gocb.ErrDocumentNotFound) {
		writeJsonFailure(w, 401, ErrUserNotFound)
		return
	} else if err != nil {
		app.logger.Printf("Error occurred looking up user: %s", err)
		writeJsonFailure(w, 500, err)
		return
	}

	var password string
	err = result.ContentAt(0, &password)
	if err != nil {
		app.logger.Printf("Error parsing password: %s", err)
		writeJsonFailure(w, 500, err)
		return
	}

	if password != reqPass {
		writeJsonFailure(w, 401, ErrBadPassword)
		return
	}

	token, err := createJwtToken(reqUser)
	if err != nil {
		app.logger.Printf("Error creating JWT token: %s", err)
		writeJsonFailure(w, 500, err)
		return
	}

	respData := jsonUserLoginResp{
		Data: jsonUserDataResp{Token: token},
	}
	respData.Context.Add(fmt.Sprintf("KV lookupin - scoped to %s.users: for password field in document %s",
		tenant, reqUser))

	encodeRespOrFail(w, respData)
}

// UserSignup performs a KV insert to create a new user, returning a JWT authentication token if the user does not
// already exist.
// POST /api/tenants/{tenant}/user/signup
func (app *TravelSampleApp) UserSignup(w http.ResponseWriter, req *http.Request) {
	var reqData jsonUserSignupReq
	if !decodeReqOrFail(w, req, &reqData) {
		return
	}

	reqUser := reqData.User
	reqPass := reqData.Password
	user := jsonUser{
		Name:     reqUser,
		Password: reqPass,
	}

	vars := mux.Vars(req)
	tenant := strings.ToLower(vars["tenant"])
	scope := app.bucket.Scope(tenant)
	users := scope.Collection("users")

	_, err := users.Insert(reqUser, user, nil)
	if errors.Is(err, gocb.ErrDocumentExists) {
		writeJsonFailure(w, 409, ErrUserExists)
		return
	} else if err != nil {
		app.logger.Printf("Error occurred inserting user: %s", err)
		writeJsonFailure(w, 500, err)
		return
	}

	token, err := createJwtToken(user.Name)
	if err != nil {
		app.logger.Printf("Error occurred creating JWT token: %s", err)
		writeJsonFailure(w, 500, err)
		return
	}

	respData := jsonUserSignupResp{
		Data: jsonUserDataResp{Token: token},
	}
	respData.Context.Add(fmt.Sprintf("KV insert - scoped to %s.users: document %s", tenant, reqUser))

	encodeRespOrFail(w, respData)
}

// UserFlights performs two KV operations to fetch all flight bookings for a user.
//    the first of the KV operations is a LookupIn on the bookings field of the user document
//    the second KV operation performs a Get to fetch the flight information for each of the user's bookings
// GET /api/tenants/{tenant}/user/{username}/flights
func (app *TravelSampleApp) UserFlights(w http.ResponseWriter, req *http.Request) {
	var authUser authedUser
	if !decodeAuthUserOrFail(w, req, &authUser) {
		return
	}

	vars := mux.Vars(req)
	username := vars["username"]
	if authUser.Name != username {
		writeJsonFailure(w, 401, ErrUsernameNotMatch)
		return
	}

	userKey := strings.ToLower(username)
	tenant := strings.ToLower(vars["tenant"])
	scope := app.bucket.Scope(tenant)
	users := scope.Collection("users")
	bookings := scope.Collection("bookings")

	res, err := users.LookupIn(userKey, []gocb.LookupInSpec{
		gocb.GetSpec("bookings", nil),
	}, nil)
	if err != nil {
		app.logger.Printf("Error occurred looking up flight bookings: %s", err)
		if errors.Is(err, gocb.ErrDocumentNotFound) {
			writeJsonFailure(w, 404, ErrUserNotFound)
			return
		}
		writeJsonFailure(w, 500, err)
		return
	}

	var flightIDs []string
	err = res.ContentAt(0, &flightIDs)
	if err != nil {
		if errors.Is(err, gocb.ErrPathNotFound) {
			respData := jsonUserFlightsResp{
				Data: []jsonBookedFlight{}, // we need to send an actual empty array rather than null.
			}
			respData.Context.Add(fmt.Sprintf("KV get - scoped to %s.users: no bookings in document %s",
				tenant, userKey))
			encodeRespOrFail(w, respData)
			return
		}
		app.logger.Printf("Error occurred parsing flight ids: %s", err)
		writeJsonFailure(w, 500, err)
		return
	}

	var flights []jsonBookedFlight
	for _, flightID := range flightIDs {
		res, err := bookings.Get(flightID, nil)
		if err != nil {
			app.logger.Printf("Error occurred getting flight: %s", err)
			writeJsonFailure(w, 500, err)
			return
		}
		var flight jsonBookedFlight
		err = res.Content(&flight)
		if err != nil {
			app.logger.Printf("Error occurred parsing flight: %s", err)
			writeJsonFailure(w, 500, err)
			return
		}
		flights = append(flights, flight)
	}

	respData := jsonUserFlightsResp{
		Data: flights,
	}
	respData.Context.Add(fmt.Sprintf("KV get - scoped to %s.users: for %d bookings in document %s",
		tenant, len(flightIDs), userKey))

	encodeRespOrFail(w, respData)
}

// UserBookFlight performs two KV operations to create a flight booking for a user.
//    the first operation performs an upsert to create a document for the flight
//    the second operation performs a mutatein on the user document to add the document ID for the flight to the users
//        bookings
// POST  /api/tenants/{tenant}/user/{username}/flights
func (app *TravelSampleApp) UserBookFlight(w http.ResponseWriter, req *http.Request) {
	var authUser authedUser
	if !decodeAuthUserOrFail(w, req, &authUser) {
		return
	}

	vars := mux.Vars(req)
	username := vars["username"]
	if authUser.Name != username {
		writeJsonFailure(w, 401, ErrUsernameNotMatch)
		return
	}

	var reqData jsonUserBookFlightReq
	if !decodeReqOrFail(w, req, &reqData) {
		return
	}
	newFlight := reqData.Flights[0]

	userKey := strings.ToLower(username)
	tenant := strings.ToLower(vars["tenant"])
	scope := app.bucket.Scope(tenant)
	users := scope.Collection("users")
	bookings := scope.Collection("bookings")

	flightID := uuid.New().String()

	_, err := bookings.Upsert(flightID, newFlight, nil)
	if err != nil {
		app.logger.Printf("Error occurred creating flight booking: %s", err)
		writeJsonFailure(w, 500, errors.New("failed to add flight data"))
	}

	_, err = users.MutateIn(userKey, []gocb.MutateInSpec{
		gocb.ArrayAppendSpec("bookings", flightID, &gocb.ArrayAppendSpecOptions{CreatePath: true}),
	}, nil)
	if err != nil {
		if errors.Is(err, gocb.ErrDocumentNotFound) {
			writeJsonFailure(w, 404, ErrUserNotFound)
			return
		}
		app.logger.Printf("Error occurred adding flight booking to user: %s", err)
		writeJsonFailure(w, 500, err)
		return
	}

	var respData jsonUserBookFlightResp
	for _, flight := range reqData.Flights {
		respData.Data.Added = append(respData.Data.Added, flight)
	}
	respData.Context.Add(fmt.Sprintf("KV MutateIn - scoped to %s.users: for bookings subdocument field in document %s",
		tenant, userKey))

	encodeRespOrFail(w, respData)
}

// HotelSearch performs a SearchQuery to find a hotel given the parameters provided, it then performs a Get operation on
// each hotel returned to get information about the hotels.
// GET /api/hotel/{description}/{location}
func (app *TravelSampleApp) HotelSearch(w http.ResponseWriter, req *http.Request) {
	reqVars := mux.Vars(req)
	description := reqVars["description"]
	location := reqVars["location"]
	scope := app.bucket.Scope("inventory")
	hotels := scope.Collection("hotel")

	qp := search.NewConjunctionQuery(search.NewTermQuery("hotel").Field("type"))

	if location != "" && location != "*" {
		qp.And(search.NewDisjunctionQuery(
			search.NewMatchPhraseQuery(location).Field("country"),
			search.NewMatchPhraseQuery(location).Field("city"),
			search.NewMatchPhraseQuery(location).Field("state"),
			search.NewMatchPhraseQuery(location).Field("address"),
		))
	}

	if description != "" && description != "*" {
		qp.And(search.NewDisjunctionQuery(
			search.NewMatchPhraseQuery(description).Field("description"),
			search.NewMatchPhraseQuery(description).Field("name"),
		))
	}

	results, err := app.cluster.SearchQuery("hotels-index", qp, &gocb.SearchOptions{Limit: 100})
	if err != nil {
		app.logger.Printf("Error occurred performing hotel search query: %s", err)
		writeJsonFailure(w, 500, err)
		return
	}

	hotelCols := []string{
		"country",
		"city",
		"state",
		"address",
		"name",
		"description",
		"type",
	}
	var respData jsonHotelSearchResp
	for results.Next() {
		res, err := hotels.Get(results.Row().ID, &gocb.GetOptions{
			Project: hotelCols,
		})
		if err != nil {
			app.logger.Printf("Error occurred fetching hotel: %s", err)
			writeJsonFailure(w, 500, err)
			return
		}

		var hotel jsonHotel
		err = res.Content(&hotel)
		if err != nil {
			app.logger.Printf("Error occurred parsing hotel: %s", err)
			writeJsonFailure(w, 500, err)
			return
		}
		respData.Data = append(respData.Data, hotel)
	}
	queryBytes, err := json.Marshal(qp)
	if err != nil {
		app.logger.Printf("Failed to marshal search query: %s", err)
	}
	if len(respData.Data) == 0 {
		if len(queryBytes) > 0 {
			respData.Context.Add(fmt.Sprintf("FTS search - scoped to: inventory.hotel (no results)\n%s", string(queryBytes)))
		} else {
			respData.Context.Add("FTS search - scoped to: inventory.hotel (no results)\n")
		}
		encodeRespOrFail(w, respData)
		return
	}
	respData.Context.Add(fmt.Sprintf("FTS search - scoped to: inventory.hotel within fields %s\n%s",
		strings.Join(hotelCols, ","), string(queryBytes)))

	encodeRespOrFail(w, respData)
}

func envFlagString(envName, name, value, usage string) *string {
	envValue := os.Getenv(envName)
	if envValue != "" {
		value = envValue
	}
	return flag.String(name, value, usage)
}

func main() {
	connStr := envFlagString("CB_HOST", "host", defaultCBHost,
		"The connection string to use for connecting to the server")
	username := envFlagString("CB_USER", "user", defaultCBUsername,
		"The username to use for authentication against the server")
	password := envFlagString("CB_PASS", "password", defaultCBPassword,
		"The password to use for authentication against the server")
	scheme := envFlagString("CB_SCHEME", "scheme", defaultCBScheme,
		"The scheme to use for connecting to couchbase. Default to couchbases - set to couchbase:// when using couchbase community edition")
	flag.Parse()

	logrusLogger := logrus.New()
	logrusLogger.SetFormatter(&logrus.JSONFormatter{})
	logrusLogger.SetOutput(os.Stdout)
	logrusLogger.SetLevel(logrus.InfoLevel)

	// Uncomment to enable the Go SDK logging.
	// gocb.SetLogger(&gocbLogWrapper{
	// 	logger: logrusLogger,
	// })

	// Connect the SDK to Couchbase Server.
	clusterOpts := gocb.ClusterOptions{
		Authenticator: gocb.PasswordAuthenticator{
			Username: *username,
			Password: *password,
		},
	}
	cluster, err := gocb.Connect(*scheme+*connStr, clusterOpts)
	if err != nil {
		panic(err)
	}

	// Create a bucket instance, which we'll need for access to scopes and collections.
	bucket := cluster.Bucket(travelSampleBucketName)

	app := &TravelSampleApp{
		cluster: cluster,
		bucket:  bucket,
		logger:  logrusLogger,
	}

	// Create a router for our server.
	r := mux.NewRouter()

	// Set up our REST endpoints.
	r.Path("/api/airports").Methods("GET").HandlerFunc(app.AirportSearch)
	r.Path("/api/flightPaths/{from}/{to}").Methods("GET").HandlerFunc(app.FlightSearch)
	r.Path("/api/tenants/{tenant}/user/login").Methods("POST").HandlerFunc(app.UserLogin)
	r.Path("/api/tenants/{tenant}/user/signup").Methods("POST").HandlerFunc(app.UserSignup)
	r.Path("/api/tenants/{tenant}/user/{username}/flights").Methods("GET").HandlerFunc(app.UserFlights)
	r.Path("/api/tenants/{tenant}/user/{username}/flights").Methods("PUT").HandlerFunc(app.UserBookFlight)
	r.Path("/api/hotels/{description}/").Methods("GET").HandlerFunc(app.HotelSearch)
	r.Path("/api/hotels/{description}/{location}/").Methods("GET").HandlerFunc(app.HotelSearch)

	// Serve swagger UI from /apidocs.
	fs := http.FileServer(http.Dir("./swaggerui"))
	http.Handle("/apidocs/", http.StripPrefix("/apidocs/", fs))

	// Serve a simple landing page from root.
	r.Path("/").Methods("GET").HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		fmt.Fprintf(w,
			`
	<h1>Go Travel Sample API</h1>
    A sample API for getting started with Couchbase Server and the Go SDK.
    <ul>
      <li><a href="/apidocs">Learn the API with Swagger, interactively</a>
      <li><a href="https://github.com/couchbaselabs/try-cb-golang">GitHub</a>
    </ul>
`,
		)
	})

	corsHandler := handlers.CORS(
		handlers.AllowedMethods([]string{"GET", "POST", "PUT", "OPTIONS", "DELETE"}),
		handlers.AllowedOrigins([]string{"*"}),
		handlers.AllowedHeaders([]string{"Access-Control-Allow-Headers", "Origin", "Content-Type", "Content-Length",
			"Accept-Encoding", "Authorization"}),
		handlers.AllowCredentials(),
	)

	// Set up our routing
	http.Handle("/", corsHandler(r))

	stop := make(chan os.Signal, 1)
	// Stop the server on interrupt
	signal.Notify(stop, os.Interrupt)

	// Listen on port 8080
	srv := &http.Server{Addr: ":8080"}
	go func() {
		if err := srv.ListenAndServe(); err != nil {
			app.logger.Printf("Error running server: %s", err)
			close(stop)
		}
	}()

	fmt.Println("Server running on", srv.Addr)
	<-stop
	srv.Shutdown(nil)
	cluster.Close(nil)
}
