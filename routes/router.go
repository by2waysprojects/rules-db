package routes

import (
	"net/http"
	"rules-db/controllers"

	"github.com/gorilla/mux"
)

func RegisterRoutes(router *mux.Router, rulesController *controllers.RulesController) {
	router.HandleFunc("/save-rules", func(w http.ResponseWriter, r *http.Request) {
		err := rulesController.LoadRules(w, r)
		if err != nil {
			http.Error(w, "Failed to save rules", http.StatusInternalServerError)
		}
	}).Methods("GET")

	router.HandleFunc("/health-module", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("OK"))
	}).Methods("GET")
}
