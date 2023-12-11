package main

import (
	"flag"
	"fmt"
	"log"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
	"sync"

	"github.com/PuerkitoBio/goquery"
	"github.com/xuri/excelize/v2"
)

type CVEInfo struct {
	Id          string
	Href        string
	Description string
	CWEId       []string
	CWEDesc     []string
}

const cwe_noinfo = "NVD-CWE-noinfo"
const cwe_other = "NVD-CWE-Other"

var cve_infos []CVEInfo
var wg sync.WaitGroup

// Flags variables
var (
	cve_keyword string
	worker_num  int
	cwe_range   int
	https_proxy string
)

func cve_info_curl(keyword string) {
	var info CVEInfo

	res, err := http.Get("https://cve.mitre.org/cgi-bin/cvekey.cgi?keyword=" + keyword)
	if err != nil {
		log.Fatal(err)
	}
	defer res.Body.Close()

	doc, err := goquery.NewDocumentFromReader(res.Body)
	if err != nil {
		log.Fatal(err)
	}

	header := doc.Find("h2:contains('Search Results')")
	table := header.NextUntil("table").Next().First()
	rows := table.Find("tr")
	rows.Each(func(i int, row *goquery.Selection) {
		cells := row.Find("td")
		cells.Each(func(j int, cell *goquery.Selection) {
			switch j {
			case 0:
				info.Id = cell.Text()
				e := cell.Find("a")
				href, exists := e.Attr("href")
				if exists {
					info.Href = "https://cve.mitre.org" + href
				}
			case 1:
				info.Description = cell.Text()
			}
		})
		if len(cells.Nodes) > 0 {
			cve_infos = append(cve_infos, info)
		}
	})
}

func cve_cwe_get(cve_info *CVEInfo, cve_name string) {
	nvd_url := "https://nvd.nist.gov/vuln/detail/" + cve_name

	res, err := http.Get(nvd_url)
	if err != nil {
		log.Fatal(err)
	}
	defer res.Body.Close()

	doc, err := goquery.NewDocumentFromReader(res.Body)
	if err != nil {
		log.Fatal(err)
	}

	h3 := doc.Find("h3:contains('Weakness Enumeration')")
	table := h3.NextAllFiltered("table").First()
	rows := table.Find("tbody tr")
	rows.Each(func(i int, row *goquery.Selection) {
		cells := row.Find("td")
		cells.Each(func(j int, cell *goquery.Selection) {
			if j == 0 {
				cve_info.CWEId = append(cve_info.CWEId, strings.TrimSpace(cell.Text()))
			}
			if j == 1 {
				cve_info.CWEDesc = append(cve_info.CWEDesc, cell.Text())
			}
		})
	})
}

func excel_output(name string) int {
	f := excelize.NewFile()
	defer func() {
		err := f.Close()
		if err != nil {
			fmt.Println(err)
		}
	}()

	// Create a new sheet.
	sheet_name := "Sheet1"
	index, err := f.NewSheet(sheet_name)
	if err != nil {
		fmt.Println(err)
		return -1
	}

	for i := 0; i < len(cve_infos); i++ {
		index := strconv.Itoa(i + 1)
		f.SetCellInt(sheet_name, "A"+index, i+1)
		f.SetCellValue(sheet_name, "B"+index, cve_infos[i].Id)
		f.SetCellHyperLink(sheet_name, "B"+index, cve_infos[i].Href, "External")
		f.SetCellValue(sheet_name, "C"+index, cve_infos[i].Description)
		// Make CWE infoes string
		cwe_infos := ""
		cnt := 0
		for j := 0; j < len(cve_infos[i].CWEId); j++ {
			cweId := cve_infos[i].CWEId[j]
			cweDesc := cve_infos[i].CWEDesc[j]
			if cweId == cwe_noinfo || cweId == cwe_other {
				continue
			}
			if j > 0 {
				cwe_infos += "\n"
			}
			cwe_infos += cweId + ": " + cweDesc
			cnt++
		}
		f.SetCellValue(sheet_name, "D"+index, cwe_infos)
	}

	// Set active sheet of the workbook.
	f.SetActiveSheet(index)

	// Save spreadsheet by the given path.
	err = f.SaveAs(name)
	if err != nil {
		fmt.Println(err)
	}

	return 0
}

func worker_range_cwe_get(start int, cwe_range int) {
	defer wg.Done()
	for i := start; i < start+cwe_range; i++ {
		cve_cwe_get(&cve_infos[i], cve_infos[i].Id)
	}
	fmt.Printf("Get %d-%d %d cwe\n", start, start+cwe_range-1, cwe_range)
}

func init() {
	flag.StringVar(&cve_keyword, "keyword", "usb", "Keyword for searching CVE list")
	flag.IntVar(&worker_num, "worker", 10, "Maximum number of concurrent coroutines")
	flag.IntVar(&cwe_range, "range", 10, "Search range for each coroutines")
	flag.StringVar(&https_proxy, "proxy", "", "Set https proxy for the entry program")
}

func main() {
	flag.Parse()

	if https_proxy != "" {
		proxy_url, err := url.Parse(https_proxy)
		if err != nil {
			fmt.Println(err)
			os.Exit(1)
		}
		http.DefaultTransport = &http.Transport{Proxy: http.ProxyURL(proxy_url)}
	}

	cve_info_curl(cve_keyword)

	cve_num := len(cve_infos)
	fmt.Printf("Get %d %s cve infos\n", cve_num, cve_keyword)

	total := cve_num
	start := 0
	n := 0
	for total > 0 {
		for i := 0; i < worker_num; i++ {
			if total <= 0 {
				break
			}
			if total < cwe_range {
				n = total
			} else {
				n = cwe_range
			}
			wg.Add(1)
			go worker_range_cwe_get(start, n)
			start += n
			total -= n
		}
		wg.Wait()
	}

	fmt.Println("Start write excel")
	excel_name := cve_keyword + "_cve.xlsx"
	excel_output(excel_name)
	fmt.Printf("Write %s ok\n", excel_name)
}
