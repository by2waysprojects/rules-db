package services

import (
	"bufio"
	"context"
	"fmt"
	"io/fs"
	"log"
	"os"
	"path/filepath"
	services "rules-db/services/model"

	"github.com/google/gonids"
	"github.com/neo4j/neo4j-go-driver/v5/neo4j"
)

type Neo4jService struct {
	Driver neo4j.DriverWithContext
	Limit  int
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

func (s *Neo4jService) LoadDirectoryToNeo4j(directoryPath string, limit int) error {

	processed := 0
	s.Limit = limit

	err := filepath.WalkDir(directoryPath, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return fmt.Errorf("error accessing path %s: %w", path, err)
		}

		if processed >= s.Limit {
			return nil
		}

		if !d.IsDir() && filepath.Ext(path) == ".rules" {
			log.Printf("Processing file: %s\n", path)
			if err := s.importRuleToNeo4j(path, processed); err != nil {
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

func (s *Neo4jService) importRuleToNeo4j(filePath string, processed int) error {
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
		if len(scanner.Text()) == 0 {
			continue
		}
		if rule, err := gonids.ParseRule(scanner.Text()); err == nil {
			if rule == nil || rule.Protocol == "" {
				continue
			}
			records = append(records, rule)
		} else {
			log.Printf("error parsing rule: %v", err)
		}
	}

	session := s.Driver.NewSession(ctx, neo4j.SessionConfig{AccessMode: neo4j.AccessModeWrite})
	defer session.Close(ctx)

	if err := s.createRules(ctx, session, records, processed); err != nil {
		return err
	}

	fmt.Println("Data successfully imported into Neo4j.")
	return nil
}

func (s *Neo4jService) createRules(ctx context.Context, session neo4j.SessionWithContext, records []*gonids.Rule, processed int) error {
	for _, record := range records {

		if processed >= s.Limit {
			break
		}

		fmt.Println(record.String())
		s.createExploit(ctx, session, record)

		query := `
		MATCH (e:L7Attack {name: $name, payload: $payload})
		CREATE (p:Packet {
			seq: $seq,
			size: $size,
			protocol: $protocol
		})-[:BELONGS_TO]->(e)
	`

		_, err := session.Run(ctx, query, map[string]interface{}{
			"name":     record.Description,
			"payload":  "",
			"seq":      0,
			"size":     0,
			"protocol": record.Protocol,
		})

		if err != nil {
			log.Printf("Error inserting record from rule %s: %v", record.Description, err)
		}

		for _, pattern := range record.Contents() {

			if pattern.Options == nil || len(pattern.Options) == 0 {
				s.createWildcard(ctx, session, record, 0, string(pattern.Pattern))
				continue
			}

			for _, option := range pattern.Options {
				fmt.Println(option.Name)
				switch option.Name {
				case "http_client_body":
					s.createBody(ctx, session, record, 0, string(pattern.Pattern))
				case "http_cookie":
					s.createCookie(ctx, session, record, 0, string(pattern.Pattern))
				case "http_header":
					s.createHeader(ctx, session, record, 0, string(pattern.Pattern))
				case "http_raw_uri":
					s.createURI(ctx, session, record, 0, string(pattern.Pattern), true)
				case "http_uri":
					s.createURI(ctx, session, record, 0, string(pattern.Pattern), false)
				case "http_method":
					s.createVerb(ctx, session, record, 0, string(pattern.Pattern))
				}
			}
		}

		processed++
	}

	return nil
}

func (s *Neo4jService) createExploit(ctx context.Context, session neo4j.SessionWithContext, record *gonids.Rule) error {
	_, err := session.Run(ctx, `
		CREATE (e:L7Attack {name: $name, payload: $payload, action: $action})
	`, map[string]interface{}{"name": record.Description, "payload": "", "action": services.Alert})
	if err != nil {
		return fmt.Errorf("error creating exploit for rule %s: %w", record.Description, err)
	}

	return nil
}

func (s *Neo4jService) createHeader(ctx context.Context, session neo4j.SessionWithContext, record *gonids.Rule, seq int, header string) error {
	_, err := session.Run(ctx, `
			MATCH (p:Packet {seq: $seq})
			MATCH (e:L7Attack {name: $name, payload: $payload})
			MATCH (p)-[:BELONGS_TO]->(e)
			CREATE (h:Header {id: $headerName})-[:IS_HEADER]->(p)
	`, map[string]interface{}{"name": record.Description, "payload": "", "seq": seq, "headerName": header})
	if err != nil {
		return fmt.Errorf("error creating header for rule %s: %w", record.Description, err)
	}

	return nil
}

func (s *Neo4jService) createVerb(ctx context.Context, session neo4j.SessionWithContext, record *gonids.Rule, seq int, verb string) error {
	_, err := session.Run(ctx, `
			MATCH (p:Packet {seq: $seq})
			MATCH (e:L7Attack {name: $name, payload: $payload})
			MATCH (p)-[:BELONGS_TO]->(e)
			CREATE (h:Verb {id: $verbName})-[:IS_VERB]->(p)
	`, map[string]interface{}{"name": record.Description, "payload": "", "seq": seq, "verbName": verb})
	if err != nil {
		return fmt.Errorf("error creating verb for rule %s: %w", record.Description, err)
	}

	return nil
}

func (s *Neo4jService) createURI(ctx context.Context, session neo4j.SessionWithContext, record *gonids.Rule, seq int, uri string, exact bool) error {
	_, err := session.Run(ctx, `
			MATCH (p:Packet {seq: $seq})
			MATCH (e:L7Attack {name: $name, payload: $payload})
			MATCH (p)-[:BELONGS_TO]->(e)
			CREATE (h:Uri {id: $uri, exact: $exact})-[:IS_URI]->(p)
	`, map[string]interface{}{"name": record.Description, "payload": "", "seq": seq, "uri": uri, "exact": exact})
	if err != nil {
		return fmt.Errorf("error creating uri for rule %s: %w", record.Description, err)
	}

	return nil
}

func (s *Neo4jService) createBody(ctx context.Context, session neo4j.SessionWithContext, record *gonids.Rule, seq int, body string) error {
	_, err := session.Run(ctx, `
			MATCH (p:Packet {seq: $seq})
			MATCH (e:L7Attack {name: $name, payload: $payload})
			MATCH (p)-[:BELONGS_TO]->(e)
			CREATE (h:Body {data: $data})-[:IS_BODY]->(p)
	`, map[string]interface{}{"name": record.Description, "payload": "", "seq": seq, "data": body})
	if err != nil {
		return fmt.Errorf("error creating body for rule %s: %w", record.Description, err)
	}

	return nil
}

func (s *Neo4jService) createCookie(ctx context.Context, session neo4j.SessionWithContext, record *gonids.Rule, seq int, cookie string) error {
	_, err := session.Run(ctx, `
			MATCH (p:Packet {seq: $seq})
			MATCH (e:L7Attack {name: $name, payload: $payload})
			MATCH (p)-[:BELONGS_TO]->(e)
			CREATE (h:Cookie {id: $cookieName})-[:IS_COOKIE]->(p)
	`, map[string]interface{}{"name": record.Description, "payload": "", "seq": seq, "cookieName": cookie})
	if err != nil {
		return fmt.Errorf("error creating cookie for rule %s: %w", record.Description, err)
	}

	return nil
}

func (s *Neo4jService) createWildcard(ctx context.Context, session neo4j.SessionWithContext, record *gonids.Rule, seq int, data string) error {
	_, err := session.Run(ctx, `
			MATCH (p:Packet {seq: $seq})
			MATCH (e:L7Attack {name: $name, payload: $payload})
			MATCH (p)-[:BELONGS_TO]->(e)
			CREATE (h:Wildcard {id: $data})-[:IS_WILDCARD]->(p)
	`, map[string]interface{}{"name": record.Description, "payload": "", "seq": seq, "data": data})
	if err != nil {
		return fmt.Errorf("error creating wildcard for rule %s: %w", record.Description, err)
	}

	return nil
}
