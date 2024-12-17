package services

import (
	"log"
)

const (
	dataPath = "data/"
)

type RulesService struct {
	Neo4jService *Neo4jService
}

func NewRulesService(neo4jService *Neo4jService) *RulesService {
	return &RulesService{
		Neo4jService: neo4jService,
	}
}

func (ms *RulesService) SaveSnortAndSuricataRules() error {
	if err := ms.Neo4jService.LoadDirectoryToNeo4j(dataPath); err != nil {
		log.Printf("Error importing results to Neo4j: %s", err)
		return err
	}

	return nil
}
