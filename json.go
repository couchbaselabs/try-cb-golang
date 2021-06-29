package main

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
	Type        string `json:"type"`
}

// jsonContext should not be confused with context.Context.
type jsonContext []string

func (c *jsonContext) Add(msg string) {
	*c = append(*c, msg)
}

type jsonFailure struct {
	Message string      `json:"message"`
	Context jsonContext `json:"context"`
}

type jsonAirportSearchResp struct {
	Data    []jsonAirport `json:"data"`
	Context jsonContext   `json:"context"`
}

type jsonFlightSearchResp struct {
	Data    []jsonFlight `json:"data"`
	Context jsonContext  `json:"context"`
}

type jsonUserLoginReq struct {
	User     string `json:"user"`
	Password string `json:"password"`
}

type jsonUserLoginResp struct {
	Data    jsonUserDataResp `json:"data"`
	Context jsonContext      `json:"context"`
}

type jsonUserSignupReq struct {
	User     string `json:"user"`
	Password string `json:"password"`
}

type jsonUserDataResp struct {
	Token string `json:"token"`
}

type jsonUserSignupResp struct {
	Data    jsonUserDataResp `json:"data"`
	Context jsonContext      `json:"context"`
}

type jsonUserFlightsResp struct {
	Data    []jsonBookedFlight `json:"data"`
	Context jsonContext        `json:"context"`
}
type jsonUserBookFlightReq struct {
	Flights []jsonBookedFlight `json:"flights"`
}

type jsonUserBookFlightDataResp struct {
	Added []jsonBookedFlight `json:"added"`
}

type jsonUserBookFlightResp struct {
	Data    jsonUserBookFlightDataResp `json:"data"`
	Context jsonContext                `json:"context"`
}

type jsonHotelSearchResp struct {
	Data    []jsonHotel `json:"data"`
	Context jsonContext `json:"context"`
}
