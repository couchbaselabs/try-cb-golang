package main

import (
	"github.com/couchbaselabs/gocb"
	"fmt"
	"time"
	"encoding/json"
	"net/http"
	"strings"
	"strconv"
	"math"
  jwt "github.com/dgrijalva/jwt-go"

)

// bucket reference
var bucket *gocb.Bucket
const kmtomiles = float64(0.621371192)
const earthRadius = float64(6371)
const distanceCostMultiplier = float64(0.1)
const averageKilometersHour = float64(800)
const layout = "01/02/2006"
const hashToken = "UNSECURE_SECRET_TOKEN"

type Airport struct {
	Airportname string `json:"airportname"`
}

type AirportIntermediary struct {
		ToAirport string `json:'toAirport,omitempty'`
	  FromAirport string `json:'fromAirport,omitempty'`
		Geo struct {
			Alt int `json:"alt"`
			Lat float64 `json:"lat"`
			Lon float64 `json:"lon"`
		} `json:"geo"`
}

type Flight struct {
	Destinationairport string `json:"destinationairport"`
	Equipment string `json:"equipment"`
	Flight string `json:"flight"`
	ID int `json:"id"`
	Name string `json:"name"`
	Sourceairport string `json:"sourceairport"`
	Utc string `json:"utc"`
	Flighttime int `json:"flighttime"`
	Price int `json:"price"`
}

type User struct {
	Type string `json:"_type"`
	ID string `json:"_id"`
	Name string `json:"name"`
	Password string `json:"password"`
	Token string `json:"token"`
	Flights []struct {
		Type string `json:"_type"`
		ID string `json:"_id"`
		Name string `json:"name"`
		Flight string `json:"flight"`
		Date string `json:"date"`
		Sourceairport string `json:"sourceairport"`
		Destinationairport string `json:"destinationairport"`
		Bookedon string `json:"bookedon"`
	} `json:"flights"`
}

type UserIntermediary struct{
	User string `json:"user"`
	Password string `json:"password"`
	Token	string `json:"token"`
}

func (u *UserIntermediary) CreateUser() bool{
	token := jwt.New(jwt.SigningMethodHS256)
	token.Claims["user"] = u.User
	if encryptedToken, err := token.SignedString([]byte(hashToken)); err != nil{
		return false
	} else {
		u.Token=encryptedToken
	}

	var newUser User
	newUser.Type = "User"
	newUser.ID = "NOT_CURRENTLY_USED"
	newUser.Name = u.User
	newUser.Password = u.Password
	newUser.Token = u.Token
	if _, err := bucket.Insert(newUser.Name, newUser, 0); err != nil{
			fmt.Println("here we didnt:",err)
			fmt.Printf("%+v",newUser)
			return false
	}
	return true
}

func (u *UserIntermediary) LoginUser() bool{
	var curUser User
	if _,err := bucket.Get(u.User,&curUser); err != nil{
		return false
	}
	if u.Password == curUser.Password {
		u.Token=curUser.Token
		return true
	}
	return false
}

func (u *UserIntermediary) CheckUserExists() bool{
	var curUser User
	if _,err := bucket.Get(u.User,&curUser); err != nil{
		return false
	}
	return true
}

func main() {
	cluster, _ := gocb.Connect("couchbase://127.0.0.1")
	bucket, _ = cluster.OpenBucket("travel-sample","")

	http.Handle("/", http.FileServer(http.Dir("./static")))
	http.HandleFunc("/api/airport/findAll", airportHandler)
	http.HandleFunc("/api/flightPath/findAll",flightPathHandler)
	http.HandleFunc("/api/user/login",loginHandler)
	fmt.Printf("Starting server on :3000\n")
	http.ListenAndServe(":3000",nil)
}

/*

	GET  /api/airport/findall
	GET /api/flightPath/findAll
	POST /api/user/login
	GET /api/user/login
	POST /api/user/flights
	GET /api/user/flights
*/
func airportHandler(w http.ResponseWriter, r *http.Request) {
//search
//token
	search := r.URL.Query().Get("search")
	//token := "raybob"
	var queryPrep string
	switch len(search) {
	case 3:
		queryPrep = "SELECT airportname FROM `travel-sample` WHERE faa ='" + strings.ToUpper(search) + "'"
	case 4:
		if s:=strings.ToUpper(search); s==search {
			queryPrep = "SELECT airportname FROM `travel-sample` WHERE faa ='" + strings.ToUpper(search) + "'"
		}else{
			queryPrep = "SELECT airportname FROM `travel-sample` WHERE airportname like '" + search + "%'"
		}
	default:
		queryPrep = "SELECT airportname FROM `travel-sample` WHERE airportname like '" + search + "%'"
	}

	myQuery := gocb.NewN1qlQuery(queryPrep)
	rows := bucket.ExecuteN1qlQuery(myQuery,nil)

	var airports []Airport
	var row Airport
	for rows.Next(&row){
		airports=append(airports,row)
	}
	bytes,_:=json.Marshal(airports)
	w.Write(bytes)
}


func flightPathHandler(w http.ResponseWriter, r *http.Request) {

	var queryPrep, queryTo, queryFrom string
	var fromLon, fromLat, toLon, toLat, dist float64
	var price, flightTime int
	var leave time.Time
	var weekday int
	var row AirportIntermediary
	var airports []AirportIntermediary
	var flight Flight
	var flights []Flight

	from := r.URL.Query().Get("from")
	to := r.URL.Query().Get("to")

	leave,_ = time.Parse(layout,r.URL.Query().Get("leave"))
	weekday = int(leave.Weekday())+1

	queryPrep = "SELECT faa as fromAirport,geo FROM `travel-sample` WHERE airportname = '" + from +
	        "' UNION SELECT faa as toAirport,geo FROM `travel-sample` WHERE airportname = '" + to + "'"

	myQuery := gocb.NewN1qlQuery(queryPrep)
	rows := bucket.ExecuteN1qlQuery(myQuery,nil)

	for rows.Next(&row) {
		airports = append(airports,row)
		if row.ToAirport!="" {
			toLat=row.Geo.Lat
			toLon=row.Geo.Lon
			queryTo=row.ToAirport
		}
		if row.FromAirport!="" {
			fromLat=row.Geo.Lat
			fromLon=row.Geo.Lon
			queryFrom=row.FromAirport
		}
		row = AirportIntermediary{}
	}
	dist = Haversine(fromLon,fromLat,toLon,toLat)
	flightTime = int(dist/averageKilometersHour)
	price = int(dist * distanceCostMultiplier)

	_ = rows.Close()

	queryPrep="SELECT r.id, a.name, s.flight, s.utc, r.sourceairport, r.destinationairport, r.equipment " +
            "FROM `travel-sample` r UNNEST r.schedule s JOIN `travel-sample` a ON KEYS r.airlineid WHERE r.sourceairport='" +
						queryFrom + "' AND r.destinationairport='" + queryTo + "' AND s.day=" + strconv.Itoa(weekday) + " ORDER BY a.name"

	myQuery = gocb.NewN1qlQuery(queryPrep)
	rows = bucket.ExecuteN1qlQuery(myQuery,nil)

	for i:=0; rows.Next(&flight);i++ {
		flight.Flighttime=flightTime
		flight.Price=price
		flights=append(flights,flight)
	}
	_ = rows.Close()
	bytes,_:=json.Marshal(flights)
	w.Write(bytes)
}

func Haversine(lonFrom float64, latFrom float64, lonTo float64, latTo float64) (distance float64) {
	var deltaLat = (latTo - latFrom) * (math.Pi / 180)
	var deltaLon = (lonTo - lonFrom) * (math.Pi / 180)

	var a = math.Sin(deltaLat / 2) * math.Sin(deltaLat / 2) +
		math.Cos(latFrom * (math.Pi / 180)) * math.Cos(latTo * (math.Pi / 180)) *
		math.Sin(deltaLon / 2) * math.Sin(deltaLon / 2)
	var c = 2 * math.Atan2(math.Sqrt(a),math.Sqrt(1-a))

	distance = earthRadius * c

	return
}

func loginHandler(w http.ResponseWriter, r *http.Request) {
	var q UserIntermediary

	switch r.Method {
		case "GET":
			q.User = r.URL.Query().Get("user")
			q.Password = r.URL.Query().Get("password")
		case "POST":
			_ = json.NewDecoder(r.Body).Decode(&q)
			// check if user exists
			if exists := q.CheckUserExists(); exists == true {
				// user exists
				bytes:=[]byte(`{"failure":"User exists, please choose a different username"}`)
				w.Write(bytes)
			}
			if created := q.CreateUser(); created == true {
				// user created
				var s struct {
					Success string `json:"success"`
				}
				s.Success=q.Token
				bytes,_:=json.Marshal(s)
				w.Write(bytes)
			}
		}
}


/*
func userFlightsHandler(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
		case "GET":

		case "POST":

	}

	*/
