package services

import (
	"bufio"
	"context"
	"fmt"
	"io/fs"
	"log"
	"os"
	"path/filepath"

	"github.com/google/gonids"
	"github.com/neo4j/neo4j-go-driver/v5/neo4j"
)

type Neo4jService struct {
	Driver neo4j.DriverWithContext
}

func NewNeo4jService(uri, username, password string) *Neo4jService {
	driver, err := neo4j.NewDriverWithContext(uri, neo4j.BasicAuth(username, password, ""))
	if err != nil {
		log.Fatalf("Failed to create Neo4j driver: %v", err)
	}
	return &Neo4jService{Driver: driver}
}

func (s *Neo4jService) Close() {
	s.Driver.Close(context.Background())
}

func (s *Neo4jService) LoadDirectoryToNeo4j(directoryPath string) error {

	// Walk through all files in the directory
	err := filepath.WalkDir(directoryPath, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return fmt.Errorf("error accessing path %s: %w", path, err)
		}

		if !d.IsDir() && filepath.Ext(path) == ".rules" {
			log.Printf("Processing file: %s\n", path)
			if err := s.importRuleToNeo4j(path); err != nil {
				log.Printf("Error processing file %s: %v", path, err)
			}
		}
		return nil
	})

	if err != nil {
		return fmt.Errorf("error walking through directory: %w", err)
	}

	log.Println("All files processed successfully.")
	return nil
}

func (s *Neo4jService) importRuleToNeo4j(filePath string) error {
	ctx := context.Background()
	// Open the CSV file
	file, err := os.OpenFile(filePath, os.O_RDWR|os.O_CREATE, os.ModePerm)
	if err != nil {
		return fmt.Errorf("error opening rule file: %w", err)
	}
	defer file.Close()

	var records []*gonids.Rule
	scanner := bufio.NewScanner(file)

	// Leer cada línea
	for scanner.Scan() {
		if rule, err := gonids.ParseRule(scanner.Text()); err == nil {
			records = append(records, rule)
		} else {
			log.Fatalf("error parsing rule: %v", err)
		}
	}

	session := s.Driver.NewSession(ctx, neo4j.SessionConfig{AccessMode: neo4j.AccessModeWrite})
	defer session.Close(ctx)

	if err := s.createRules(ctx, session, records); err != nil {
		return err
	}

	fmt.Println("Data successfully imported into Neo4j.")
	return nil
}

func (s *Neo4jService) createRules(ctx context.Context, session neo4j.SessionWithContext, records []*gonids.Rule) error {
	for _, record := range records {

		s.createExploit(ctx, session, record)

		query := `
		MATCH (e:Exploit {name: $name, payload: $payload})
		CREATE (p:Packet {
			seq: $seq,
			size: $size,
			protocol: $protocol,
			request: $request,
			body: $body
		})-[:BELONGS_TO]->(e)
	`

		// Execute the query
		_, err := session.Run(ctx, query, map[string]interface{}{
			"name":     record.Description,
			"payload":  "",
			"seq":      "",
			"size":     "",
			"protocol": record.Protocol,
			"request":  string(record.PCREs()[0].Pattern),
			"body":     record.LastContent().String(),
		})
		if err != nil {
			log.Printf("Error inserting record from rule %s: %v", record.Description, err)
		}
	}

	return nil
}

func (s *Neo4jService) createExploit(ctx context.Context, session neo4j.SessionWithContext, record *gonids.Rule) error {
	_, err := session.Run(ctx, `
		CREATE (e:Exploit {name: $name, payload: $payload})
	`, map[string]interface{}{"name": record.Description, "payload": ""})
	if err != nil {
		return fmt.Errorf("error creating exploit for rule %s: %w", record.Description, err)
	}

	return nil
}
