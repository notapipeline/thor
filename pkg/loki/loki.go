package loki

import (
	"encoding/json"
	"fmt"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/grafana/loki/pkg/logcli/client"
	"github.com/grafana/loki/pkg/logcli/query"
	"github.com/grafana/loki/pkg/loghttp"
	"github.com/grafana/loki/pkg/logproto"
	"github.com/grafana/loki/pkg/logqlmodel"
	"github.com/notapipeline/thor/pkg/config"
	log "github.com/sirupsen/logrus"
)

const (
	BATCH_SIZE int = 1000
	LIMIT      int = 10000

	// duration is for the last year
	DURATION int64 = int64(time.Hour) * 168 * 52
)

var (
	ignore_words []string = []string{
		"delete",
		"destroy",
		"undelete",
		"metadata",
	}

	ignore_paths []string = []string{
		"sys",
	}
)

type Result struct {
	Namespace string
	Paths     []string
}

type SimpleMessage struct {
	Time    string `json:"time"`
	Message string `json:"message"`
	Host    string `json:"host"`
}

func (r *Result) Contains(what string) bool {
	for _, p := range r.Paths {
		if p == what {
			return true
		}
	}
	return false
}

type streamEntryPair struct {
	entry  loghttp.Entry
	labels loghttp.LabelSet
}

type Loki struct {
	client *client.DefaultClient
}

func NewLoki(c *config.LokiConfig) (*Loki, error) {
	loki := Loki{
		client: &client.DefaultClient{
			Address:  fmt.Sprintf("http://%s:%d", c.Server, c.Port),
			Username: c.Username,
			Password: c.Password,
		},
	}
	//
	return &loki, nil
}

func (loki *Loki) Search(user string, results *[]Result) error {
	defaultEnd := time.Now()
	since := time.Duration(DURATION)
	defaultStart := defaultEnd.Add(-since)

	// For vault audit logs, we can use a simplified loki search string
	// to simply regex for the user.
	//
	// Validation on the user email must be done at a higher level to
	// protect the search query from abuse.
	queryString := fmt.Sprintf("{active=\"true\"} |~ \".*%s*\" |= \"type=response\" | logfmt", user)
	searchQuery := &query.Query{
		QueryString: queryString,
		Start:       defaultStart,
		End:         defaultEnd,
		BatchSize:   BATCH_SIZE,
		Limit:       LIMIT,
	}

	return loki.search(searchQuery, results)
}

func (loki *Loki) search(q *query.Query, results *[]Result) (err error) {
	var entries []streamEntryPair
	entries, err = loki.query(q)
	if err != nil {
		return
	}

	for _, entry := range entries {
		requestEntry := make(map[string]interface{})
		responseEntry := make(map[string]interface{})
		labels := entry.labels.Map()
		s := strings.ReplaceAll(labels["request"], "=>", ":")
		s = strings.ReplaceAll(s, "nil", "null")
		if err := json.Unmarshal([]byte(s), &requestEntry); err != nil {
			log.Errorf("JSON UNPACK: ", err)
		}

		s = strings.ReplaceAll(labels["response"], "=>", ":")
		s = strings.ReplaceAll(s, "nil", "null")
		if err := json.Unmarshal([]byte(s), &responseEntry); err != nil {
			log.Errorf("JSON UNPACK: ", err)
		}

		if data, ok := responseEntry["data"]; ok {
			paths := make([]string, 0)
			for k := range data.(map[string]interface{}) {
				var pathSegments []string = strings.Split(k, "/")
				if len(pathSegments) > 1 && k[len(k)-1:] != "/" {
					for _, ignore := range ignore_words {
						if pathSegments[1] == ignore {
							pathSegments[1] = "data"
						}
					}

					if pathSegments[0] != "sys" {
						paths = append(paths, strings.Join(pathSegments, "/"))
					}
				}
			}
			if len(paths) == 0 {
				continue
			}
			var path string = paths[0]
			namespace := requestEntry["namespace"].(map[string]interface{})["path"]
			if namespace != nil && len(strings.Split(path, "/")) > 1 {
				var skipAddNamespace bool = false
				for i, v := range *results {
					if v.Namespace == strings.Trim(namespace.(string), "/") {
						if !v.Contains(path) {
							(*results)[i].Paths = append(v.Paths, path)
						}
						skipAddNamespace = true
					}
				}
				if !skipAddNamespace {
					result := Result{
						Namespace: strings.Trim(namespace.(string), "/"),
						Paths:     make([]string, 0),
					}
					result.Paths = append(result.Paths, path)
					*results = append(*results, result)
				}
			}
		}
	}

	return nil
}

func (loki *Loki) ApplicationLogs(hosts []string, result *chan SimpleMessage, done chan bool) error {
	// querystring needs backticks inside it and escaping is a nightmare
	queryString := `{thorhost=~"` + strings.Join(hosts, "|") + `"} | logfmt | line_format ` + "`{{" +
		` .MESSAGE | replace "\\" "" ` + "}}`" +
		` | logfmt | _EXE=~".*thor" or ProviderName="thor.exe" | __error__ =""`

	end := time.Now()
	start := end.Add(-time.Duration(5 * time.Second))

	log.Info(queryString)
	completed := make(map[string]bool)

	for _, host := range hosts {
		completed[host] = false
	}

	go func() {
		for {
			select {
			case <-time.Tick(100 * time.Microsecond):
				end = time.Now()
				searchQuery := &query.Query{
					QueryString: queryString,
					Start:       start,
					End:         end,
					BatchSize:   BATCH_SIZE,
					Limit:       LIMIT,
					Forward:     true,
				}

				results, err := loki.getLogMessage(searchQuery)
				if err != nil {
					log.Error(err)
				} else {
					log.Infof("LOKI - Recieved %d results", len(results))
					for _, r := range results {
						log.Info(r.Message)
						if !completed[r.Host] {
							*result <- r
						}
						if strings.ToLower(r.Message) == "completed rotation" {
							completed[r.Host] = true
						}

						var complete bool = true
						for _, v := range completed {
							if !v {
								complete = false
							}
						}

						if complete {
							done <- true
							return
						}
					}
				}
			}
		}
	}()
	return nil
}

func (loki *Loki) getLogMessage(q *query.Query) (results []SimpleMessage, err error) {
	results = make([]SimpleMessage, 0)
	entries, err := loki.query(q)
	if err != nil {
		return
	}

	log.Infof("LOKI - getLogMessage - Found %d entries", len(entries))
	for _, entry := range entries {
		var (
			message string
			host    string
			ok      bool
		)

		labels := entry.labels.Map()
		host = labels["thorhost"]
		if _, ok = labels["msg"]; ok {
			message = labels["msg"]
		} else if _, ok = labels["EventData"]; ok {
			reg, _ := regexp.Compile(`[\[\]"]`)
			message = reg.ReplaceAllString(labels["EventData"], "")
		}

		if len(message) == 0 {
			continue
		}
		results = append(results, SimpleMessage{
			Time:    entry.entry.Timestamp.Format("2006-01-02 15:04:05"),
			Message: message,
			Host:    host,
		})
	}
	return
}

// The following search/parseStreams functions are re-written from
// https://github.com/grafana/loki/blob/main/pkg/logcli/query/query.go
// as this is the simplest form I can understand to interact with the
// loki query mechanism...
func (loki *Loki) query(q *query.Query) (entries []streamEntryPair, err error) {
	entries = make([]streamEntryPair, 0)
	var (
		resultLength int       = 0
		total        int       = 0
		start        time.Time = q.Start
		end          time.Time = q.End
		direction              = logproto.BACKWARD
		lastEntry    []*loghttp.Entry
	)

	if q.Forward {
		direction = logproto.FORWARD
	}

	log.Debugf("Entering search loop 1 with %d, %d", total, q.Limit)
	for total < q.Limit {
		bs := q.BatchSize
		if q.Limit-total < q.BatchSize {
			bs = q.Limit - total + len(lastEntry)
		}

		var resp *loghttp.QueryResponse
		resp, err = loki.client.QueryRange(q.QueryString, bs, start, end, direction, q.Step, q.Interval, q.Quiet)
		if err != nil {
			log.Errorf("LOKI LOOP FOUND ERROR : ", err)
			return
		}

		if resp.Data.Result.Type() != logqlmodel.ValueTypeStreams {
			err = fmt.Errorf("Invalid type for query response. Wanted %q, got %q", logqlmodel.ValueTypeStreams, resp.Data.Result.Type())
			return
		}

		resultLength, lastEntry = loki.parseStreams(resp.Data.Result.(loghttp.Streams), &entries, lastEntry, q.Forward)
		if resultLength <= 0 {
			log.Debug("No results in current batch")
			break
		}

		if len(lastEntry) == 0 {
			log.Debug("No value for last entry")
			break
		}

		if resultLength == q.Limit {
			log.Warn("Result limit hit")
			break
		}

		if len(lastEntry) >= q.BatchSize {
			err = fmt.Errorf("Invalid batch size %v, the next query will have %v overlapping entries "+
				"(there will always be 1 overlapping entry but Loki allows multiple entries to have "+
				"the same timestamp, so when a batch ends in this scenario the next query will include "+
				"all the overlapping entries again).  Please increase your batch size to at least %v to account "+
				"for overlapping entryes\n", q.BatchSize, len(lastEntry), len(lastEntry)+1)
			return
		}

		total += resultLength
		if q.Forward {
			start = lastEntry[0].Timestamp
		} else {
			end = lastEntry[0].Timestamp.Add(1 * time.Nanosecond)
		}
	}
	return
}

func (loki *Loki) parseStreams(
	streams loghttp.Streams, entries *[]streamEntryPair,
	lastEntry []*loghttp.Entry, forward bool) (int, []*loghttp.Entry) {

	allEntries := make([]streamEntryPair, 0)
	for _, s := range streams {
		for _, e := range s.Entries {
			allEntries = append(allEntries, streamEntryPair{
				entry:  e,
				labels: s.Labels,
			})
		}
	}

	if forward {
		sort.Slice(allEntries, func(i, j int) bool { return allEntries[i].entry.Timestamp.Before(allEntries[j].entry.Timestamp) })
	} else {
		sort.Slice(allEntries, func(i, j int) bool { return allEntries[i].entry.Timestamp.After(allEntries[j].entry.Timestamp) })
	}

	var length int = 0
	for _, e := range allEntries {
		if len(lastEntry) > 0 && e.entry.Timestamp == lastEntry[0].Timestamp {
			skip := false
			for _, le := range lastEntry {
				if e.entry.Line == le.Line {
					skip = true
				}
			}
			if skip {
				continue
			}
		}
		*entries = append(*entries, e)
		length++
	}

	if len(allEntries) == 0 {
		return 0, nil
	}
	lel := []*loghttp.Entry{}
	le := allEntries[len(allEntries)-1].entry
	for i, e := range allEntries {
		if e.entry.Timestamp.Equal(le.Timestamp) {
			lel = append(lel, &allEntries[i].entry)
		}
	}
	return length, lel
}
