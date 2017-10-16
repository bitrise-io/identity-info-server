package main

import (
	"fmt"
	"net/http"
	"os"

	"github.com/gorilla/mux"
)

func main() {
	router := mux.NewRouter().StrictSlash(true)
	router.HandleFunc("/certificate/url", CertFromURL).Methods("POST")
	router.HandleFunc("/certificate", CertFromContent).Methods("POST")
	router.HandleFunc("/profile/url", ProfFromURL).Methods("POST")
	router.HandleFunc("/profile", ProfFromContent).Methods("POST")
	router.HandleFunc("/", index).Methods("GET")

	if err := http.ListenAndServe(":"+os.Getenv("PORT"), router); err != nil {
		fmt.Printf("Failed to listen, error: %s\n", err)
	}
}

func index(w http.ResponseWriter, r *http.Request) {
	fmt.Fprintln(w, "Welcome!")
}
