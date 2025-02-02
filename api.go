package main

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"strings"
	"sync"

	"github.com/gorilla/mux"
	"github.com/jinzhu/copier"
	log "github.com/sirupsen/logrus"
	"github.com/zmap/zdns/iohandlers"
	"github.com/zmap/zdns/pkg/zdns"
)

type StreamOutputHandler struct {
	writer http.ResponseWriter
}

// NewStreamOutputHandler returns a new StreamOutputHandler that will write results to the given http.ResponseWriter.
func NewStreamOutputHandler(w http.ResponseWriter) *StreamOutputHandler {
	return &StreamOutputHandler{
		writer: w,
	}
}

// WriteResults takes a channel of strings and writes them to the embedded http.ResponseWriter.
// The WaitGroup is used to signal when the write operation is complete. The function will block until the
// channel is closed. If the http.ResponseWriter implements the http.Flusher interface, WriteResults will
// call Flush() after writing all the results in order to ensure that the writes are sent to the client as
// soon as possible.
func (h *StreamOutputHandler) WriteResults(results <-chan string, wg *sync.WaitGroup) error {
	defer (*wg).Done()
	for n := range results {
		h.writer.Write([]byte(n + "\n"))
	}

	if f, ok := h.writer.(http.Flusher); ok {
		f.Flush()
	}
	return nil
}

type DNSRequests struct {
	Module  string   `json:"module"`
	Queries []string `json:"queries"`
}

type APIResultType struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
}

// APIResult writes a JSON response with the given code and message to the
// given http.ResponseWriter. It will also set the HTTP status code to 400 if
// the code is 2000 or higher.
func APIResult(w http.ResponseWriter, code int, message string) {
	w.Header().Set("Content-Type", "application/json")
	if code >= 2000 {
		w.WriteHeader(http.StatusBadRequest)
	}
	json.NewEncoder(w).Encode(APIResultType{Code: code,
		Message: message,
	})
}

// pingRequest is the handler for the GET /ping route. It returns a JSON result
// with code 1000 and the message "Command completed successfully".
func pingRequest(w http.ResponseWriter, r *http.Request) {
	APIResult(w, 1000, "Command completed successfully")
}

// notFound is the handler for any route that doesn't match any of the defined routes.
// It returns a JSON result with code 2000 and the message "Unknown command".
func notFound(w http.ResponseWriter, r *http.Request) {
	APIResult(w, 2000, "Unknown command")
}

// runModule is the main handler function for the API server. It handles both form encoded
// and JSON encoded requests. It extracts the lookup type from the URL or the request
// body, and then runs the lookup using the zdns library.
func runModule(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	w.Header().Set("Content-Type", "application/json")
	var dr DNSRequests
	var gc zdns.GlobalConf
	copier.Copy(&gc, &GC)

	// setup i/o
	gc.OutputHandler = NewStreamOutputHandler(w)

	req_content_type := r.Header.Get("Content-Type")
	if req_content_type == "application/json" {
		reqBody, _ := ioutil.ReadAll(r.Body)

		err := json.Unmarshal(reqBody, &dr)
		if err != nil {
			APIResult(w, 2001, "Failed to decode request: "+err.Error())
			return
		}

		if dr.Module == "" {
			dr.Module = "A"
		}

		if len(dr.Queries) < 1 {
			APIResult(w, 2005, "Queries array empty.")
			return
		}

		t := strings.NewReader(strings.Join(dr.Queries, "\n"))
		gc.InputHandler = iohandlers.NewStreamInputHandler(t)
	} else {
		if val, ok := vars["lookup"]; ok {
			dr.Module = val
		} else {
			dr.Module = "A"
		}

		gc.InputHandler = iohandlers.NewStreamInputHandler(r.Body)
	}

	gc.Module = strings.ToUpper(dr.Module)
	factory := zdns.GetLookup(gc.Module)
	if factory == nil {
		APIResult(w, 2005, "Invalid lookup module specified.")
		return
	}
	factory.SetFlags(GC.Flags)

	// allow the factory to initialize itself
	if err := factory.Initialize(&gc); err != nil {
		APIResult(w, 2400, "Factory was unable to initialize: "+err.Error())
	}

	// run it.
	if err := zdns.DoLookups(factory, &gc); err != nil {
		APIResult(w, 2400, "Unable to run lookups:"+err.Error())
	}

	// allow the factory to finalize itself
	if err := factory.Finalize(); err != nil {
		APIResult(w, 2400, "Factory was unable to finalize:"+err.Error())
	}
}

// startServer sets up the gorilla/mux router and starts the server on the configured address and port.
// It will serve the following endpoints:
// - POST /job/{lookup}: runs a job for the given lookup type
// - GET /ping: returns a simple "Call is ok" message
// - Anything else: returns a 404 JSON response
func startServer() {
	r := mux.NewRouter().StrictSlash(true)
	r.HandleFunc("/job/{lookup}", runModule).Methods("POST")
	r.HandleFunc("/job", runModule).Methods("POST")
	r.HandleFunc("/ping", pingRequest)
	r.NotFoundHandler = http.HandlerFunc(notFound)
	log.Info("Starting Server on ", GC.ApiIP, ":", GC.ApiPort)
	log.Fatal(http.ListenAndServe(fmt.Sprintf("%s:%v", GC.ApiIP, GC.ApiPort), r))
}
