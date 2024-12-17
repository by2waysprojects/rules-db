package controllers

import (
	"fmt"
	"log"
	"net/http"
	"rules-db/services"
)

type RulesController struct {
	DBService    *services.Neo4jService
	RulesService *services.RulesService
}

func NewRulesController(dbService *services.Neo4jService, metasploitService *services.RulesService) *RulesController {
	return &RulesController{DBService: dbService, RulesService: metasploitService}
}

func (mc *RulesController) LoadRules(w http.ResponseWriter, r *http.Request) error {
	log.Println("Saving all rules from Suricata and Snort Layer 7...")

	err := mc.RulesService.SaveSnortAndSuricataRules()
	if err != nil {
		http.Error(w, "Failed saving rules", http.StatusInternalServerError)
		return err
	}

	w.WriteHeader(http.StatusOK)
	fmt.Fprintln(w, "All rules are correctly saved")
	return nil
}
