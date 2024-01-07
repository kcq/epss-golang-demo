package main

import (
	"fmt"
	"context"

	"github.com/slimtoolkit/slim/pkg/vulnerability/epss"
	"github.com/slimtoolkit/slim/pkg/vulnerability/epss/api"
	"github.com/slimtoolkit/slim/pkg/vulnerability/epss/client"
	"github.com/slimtoolkit/slim/pkg/util/jsonutil"
)

func main() {
	cveID := "cve-2022-26332"
	apiInst := api.New(api.Options{Debug: true})

	// Low Level "API" interface examples:

	fmt.Printf("\n[1] LOOKUP EPSS FOR A CVE: %s\n", cveID)
	lookupApiReply, err := apiInst.LookupCall(
		context.Background(),
		[]string{cveID},
		api.CallOptions{
			Date:   "2023-11-24",
		})

	if err != nil {
		panic(err)
	}

	if lookupApiReply == nil {
		panic("lookupApiReply is nil")
	}

	fmt.Printf("\n[1][apiInst.LookupCall] REPLY DATA:%s\n\n", jsonutil.ToPretty(lookupApiReply))

	fmt.Printf("\n[2] LOOKUP EPSS FOR A CVE IN CSV: %s\n", cveID)
	lookupResultRawCSV, err := apiInst.GenericLookupCall(
		context.Background(),
		[]string{cveID},
		epss.OutCSV)
	if err != nil {
		panic(err)
	}

	fmt.Printf("[2] Raw lookup CVE(%s) - CSV: %#v\n\n", cveID, lookupResultRawCSV)

	fmt.Printf("\n[3]LOOKUP EPSS FOR A CVE IN YAML: %s\n", cveID)
	lookupResultRawYAML, err := apiInst.GenericLookupCall(
		context.Background(),
		[]string{cveID},
		epss.OutYAML)
	if err != nil {
		panic(err)
	}

	fmt.Printf("[3] Raw lookup CVE(%s) - YAML: %#v\n\n", cveID, lookupResultRawYAML)

	// Higher Level "Client" interface examples:

	clientInst := client.New(client.Options{Debug: true})

	fmt.Printf("\n[4] LOOKUP EPSS FOR A CVE FOR A SPECIFIC DATE: %s (Date='2023-11-24')\n", cveID)
	scoreWithDate, lookupResultWithDate, err := clientInst.LookupScore(
		context.Background(),
		cveID,
		client.CallOptions{
			Date: epss.Date(2023, 11, 24),
		})

	if err != nil {
		panic(err)
	}

	fmt.Printf("\n[4.a][clientInst.LookupScore] RESULT DATA (scoreWithDate):%s \n(scoreWithDate.DS: %#v)\n\n", 
	jsonutil.ToPretty(scoreWithDate), scoreWithDate)
	fmt.Printf("\n[4.b][clientInst.LookupScore] RESULT DATA (lookupResultWithDate):%s\n\n", jsonutil.ToPretty(lookupResultWithDate))

	fmt.Printf("\n[5] LOOKUP THE LATEST EPSS FOR A CVE: %s\n", cveID)
	score, lookupResult, err := clientInst.LookupScore(
		context.Background(),
		cveID)

	if err != nil {
		panic(err)
	}

	fmt.Printf("\n[5.a][clientInst.LookupScore] RESULT DATA (score):%s\n\n", jsonutil.ToPretty(score))
	fmt.Printf("\n[5.b][clientInst.LookupScore] RESULT DATA (lookupResult):%s\n\n", jsonutil.ToPretty(lookupResult))

	fmt.Printf("\n[6] LOOKUP THE LATEST EPSS FOR A CVE WITH EPSS HISTORY: %s\n", cveID)
	scoreWithHistory, lookupResultWithHistory, err := clientInst.LookupScoreWithHistory(
		context.Background(),
		cveID)

	if err != nil {
		panic(err)
	}

	fmt.Printf("\n[6.a][clientInst.LookupScore/History] RESULT DATA (scoreWithHistory):%s\n\n", jsonutil.ToPretty(scoreWithHistory))
	fmt.Printf("\n[6.b][clientInst.LookupScore/History] RESULT DATA (lookupResultWithHistory):%s\n\n", jsonutil.ToPretty(lookupResultWithHistory))

	lookupCVEList := []string{cveID, "CVE-2022-27225"}
	fmt.Printf("\n[7] LOOKUP THE LATEST EPSS DATA FOR A LIST OF CVEs: %+v\n", lookupCVEList)
	scores, lookupScoresResult, err := clientInst.LookupScores(
		context.Background(),
		lookupCVEList,
	)

	if err != nil {
		panic(err)
	}

	fmt.Printf("\n[7.a][clientInst.LookupScores] RESULT DATA (scores):%s\n\n", jsonutil.ToPretty(scores))
	fmt.Printf("\n[7.b][clientInst.LookupScores] RESULT DATA (lookupScoresResult):%s\n\n", jsonutil.ToPretty(lookupScoresResult))

	fmt.Printf("\n[8] LOOKUP EPSS FOR A LIST OF CVEs FOR A SPECIFIC DATE AND WITH EPSS HISTORY: %+v\n", lookupCVEList)
	scoresWithHistory, lookupScoresResultWithHistory, err := clientInst.LookupScoresWithHistory(
		context.Background(),
		lookupCVEList,
		client.CallOptions{
			Date: epss.Date(2023, 11, 24),
		})

	if err != nil {
		panic(err)
	}

	fmt.Printf("\n[8.a][clientInst.LookupScoresResultWithHistory] RESULT DATA (scoresWithHistory):%s\n\n", jsonutil.ToPretty(scoresWithHistory))
	fmt.Printf("\n[8.b][clientInst.LookupScoresResultWithHistory] RESULT DATA (lookupScoresResultWithHistory):%s\n\n", jsonutil.ToPretty(lookupScoresResultWithHistory))

	cveIDPattern := "2023"
	fmt.Printf("\n[9] LIST EPSS RECORDS THAT MATCH THE PROVIDED FILTER\n")
	scoreList, listScoresResult, err := clientInst.ListScores(
		context.Background(),
		client.FilteredCallOptions{
			CveIDPattern: cveIDPattern,
			ScoreGt: 0.1,
			PercentileGt: 0.98,
			DaysSinceAdded: 100,
			//Date: epss.Date(2023, 11, 24), //'date' works too
		})
	if err != nil {
		panic(err)
	}

	fmt.Printf("\n[9] clientInst.ListScores(%s):[status=%s total=%d r.count=%d]\n\n",
	cveIDPattern,
	listScoresResult.Status,
	listScoresResult.Total,
	len(scoreList))

	fmt.Printf("\n[9] clientInst.ListScores(%s): DATA:%s\n\n", cveIDPattern, jsonutil.ToPretty(scoreList))

	fmt.Printf("\n[10] LIST EPSS RECORDS THAT MATCH THE PROVIDED FILTER WITH HISTORY\n")
	scoreListWithHistory, listScoresResultWithHistory, err := clientInst.ListScoresWithHistory(
		context.Background(),
		client.FilteredCallOptions{
			CallOptions: client.CallOptions{
				Date: epss.Date(2023, 11, 24),
			},
			CveIDPattern: cveIDPattern,
			ScoreGt: 0.1,
			PercentileGt: 0.98,
			DaysSinceAdded: 100,
		})
	if err != nil {
		panic(err)
	}

	fmt.Printf("\n[10] clientInst.ListScoresWithHistory(%s):[status=%s total=%d r.count=%d]\n\n",
	cveIDPattern,
	listScoresResultWithHistory.Status,
	listScoresResultWithHistory.Total,
	len(scoreListWithHistory))

	fmt.Printf("\n[10] clientInst.ListScoresWithHistory(%s): DATA:%s\n\n", cveIDPattern, jsonutil.ToPretty(scoreListWithHistory))
}
