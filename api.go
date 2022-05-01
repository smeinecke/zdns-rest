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

func NewStreamOutputHandler(w http.ResponseWriter) *StreamOutputHandler {
	return &StreamOutputHandler{
		writer: w,
	}
}

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
	Module   string   `json:"module"`
	Requests []string `json:"requests"`
}

type APIResultType struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
}

func APIResult(w http.ResponseWriter, code int, message string) {
	w.Header().Set("Content-Type", "application/json")
	if code >= 2000 {
		w.WriteHeader(http.StatusBadRequest)
	}
	json.NewEncoder(w).Encode(APIResultType{Code: code,
		Message: message,
	})
}

func info(w http.ResponseWriter, r *http.Request) {
	APIResult(w, 1000, "Call is ok")
}

func notFound(w http.ResponseWriter, r *http.Request) {
	APIResult(w, 2000, "Unknown command")
}

func runJob(w http.ResponseWriter, r *http.Request) {
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

		if len(dr.Requests) < 1 {
			APIResult(w, 2005, "Requests array empty.")
			return
		}

		t := strings.NewReader(strings.Join(dr.Requests, "\n"))
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

func startServer(ApiIp string, ApiPort int) {
	r := mux.NewRouter().StrictSlash(true)
	r.HandleFunc("/dns/{lookup}", runJob).Methods("POST")
	r.HandleFunc("/info", info)
	r.NotFoundHandler = http.HandlerFunc(notFound)
	log.Info("Starting Server on ", ApiIP, ":", ApiPort)
	log.Fatal(http.ListenAndServe(fmt.Sprintf("%s:%v", ApiIP, ApiPort), r))
}
