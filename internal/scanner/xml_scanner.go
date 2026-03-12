package scanner

import (
	"bytes"
	"encoding/xml"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/joern-audit/joern_audit/internal/domain"
)

const XMLSQLIRuleID = "XML-SQLI-001"

var reDollarParam = regexp.MustCompile(`\$\{[^}]+\}`)

var sqlStatementTags = map[string]bool{
	"select": true,
	"insert": true,
	"update": true,
	"delete": true,
}

type xmlStatement struct {
	ID        string
	Type      string
	ParamType string
	SQL       string
	Line      int
}

// ScanXML recursively walks target for MyBatis mapper XML files and returns
// SQL injection candidates for any ${xxx} patterns found.
func ScanXML(target string) ([]domain.Candidate, error) {
	var candidates []domain.Candidate

	err := filepath.WalkDir(target, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return nil
		}
		if d.IsDir() || !strings.HasSuffix(strings.ToLower(path), ".xml") {
			return nil
		}
		found, ferr := scanXMLFile(path)
		if ferr != nil {
			return nil
		}
		candidates = append(candidates, found...)
		return nil
	})
	if err != nil {
		return nil, err
	}
	return candidates, nil
}

func scanXMLFile(filePath string) ([]domain.Candidate, error) {
	data, err := os.ReadFile(filePath)
	if err != nil {
		return nil, err
	}

	if !strings.Contains(string(data), "<mapper") {
		return nil, nil
	}

	namespace, stmts, err := parseMapperXML(data)
	if err != nil || namespace == "" {
		return nil, nil
	}

	var candidates []domain.Candidate
	for _, stmt := range stmts {
		matches := reDollarParam.FindAllString(stmt.SQL, -1)
		if len(matches) == 0 {
			continue
		}

		seen := make(map[string]bool)
		var unique []string
		for _, m := range matches {
			if !seen[m] {
				seen[m] = true
				unique = append(unique, m)
			}
		}

		sqlPreview := strings.TrimSpace(stmt.SQL)
		if len(sqlPreview) > 300 {
			sqlPreview = sqlPreview[:300] + "..."
		}

		paramList := strings.Join(unique, ", ")
		message := fmt.Sprintf(
			"MyBatis XML SQL Injection: unsafe ${} in %s.%s, params: %s",
			namespace, stmt.ID, paramList,
		)

		c := domain.Candidate{
			RuleID:     XMLSQLIRuleID,
			Severity:   "high",
			FilePath:   filePath,
			LineNumber: stmt.Line,
			Message:    message,
			CPGEvidence: &domain.CPGEvidence{
				JoernQuery: fmt.Sprintf(
					"XML-SQLI: ${} in <%s id=%q> namespace=%s",
					stmt.Type, stmt.ID, namespace,
				),
				CallChain: []string{namespace + "#" + stmt.ID},
				TaintFlow: []domain.TaintFlowNode{
					{
						File: filePath,
						Line: stmt.Line,
						Expr: fmt.Sprintf(
							"<%s id=%q parameterType=%q> SQL: %s",
							stmt.Type, stmt.ID, stmt.ParamType, sqlPreview,
						),
						NodeType: "SINK",
					},
				},
			},
			Status:     domain.StatusPending,
			Confidence: 0.8,
		}
		candidates = append(candidates, c)
	}

	return candidates, nil
}

func parseMapperXML(data []byte) (namespace string, stmts []xmlStatement, err error) {
	dec := xml.NewDecoder(bytes.NewReader(data))
	dec.Strict = false
	lineOf := buildLineCounter(data)

	var (
		inStmt    bool
		stmtDepth int
		cur       xmlStatement
	)

	for {
		startOffset := dec.InputOffset()
		tok, terr := dec.Token()
		if terr != nil {
			break
		}

		switch t := tok.(type) {
		case xml.StartElement:
			name := t.Name.Local

			if name == "mapper" {
				for _, a := range t.Attr {
					if a.Name.Local == "namespace" {
						namespace = a.Value
					}
				}
			}

			if !inStmt && sqlStatementTags[name] {
				inStmt = true
				stmtDepth = 1
				cur = xmlStatement{
					Type: name,
					Line: lineOf(int(startOffset)),
				}
				for _, a := range t.Attr {
					switch a.Name.Local {
					case "id":
						cur.ID = a.Value
					case "parameterType":
						cur.ParamType = a.Value
					}
				}
			} else if inStmt {
				stmtDepth++
			}

		case xml.EndElement:
			if inStmt {
				stmtDepth--
				if stmtDepth == 0 {
					stmts = append(stmts, cur)
					inStmt = false
					cur = xmlStatement{}
				}
			}

		case xml.CharData:
			if inStmt {
				cur.SQL += string(t)
			}
		}
	}

	return namespace, stmts, nil
}

func buildLineCounter(data []byte) func(offset int) int {
	return func(offset int) int {
		if offset > len(data) {
			offset = len(data)
		}
		line := 1
		for i := 0; i < offset; i++ {
			if data[i] == '\n' {
				line++
			}
		}
		return line
	}
}
