package main

import (
	"btplayer/search"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"time"

	"github.com/antchfx/xquery/html"
)

type plugin struct {
}

var mainUrl = "https://btlibrary.xyz/"
var moduleName = "btlibrary"
var httpClient = &http.Client{
	Timeout: 5 * time.Second,
	CheckRedirect: func(req *http.Request, via []*http.Request) error {
		return http.ErrUseLastResponse
	},
}

func init() {
	search.Register(plugin{})
	log.Println(fmt.Sprintf("%v init ok.", moduleName))
}

func matchInfoHash(u string) string {
	return regexp.MustCompile("item/([a-z0-9]*)?/").FindStringSubmatch(u)[1]
}

func parseRet(body io.ReadCloser) (ret []search.Result, err error) {
	doc, err := htmlquery.Parse(body)
	if err != nil {
		return
	}

	nodes := htmlquery.Find(doc, "/html/body/div[1]/div[2]/div/div[@class='item']")
	for _, node := range nodes {
		r := search.Result{}
		a := htmlquery.FindOne(node, "//div/div/a")
		r.InfoHash = matchInfoHash(htmlquery.SelectAttr(a, "href"))
		for c := a.FirstChild; c != nil; c = c.NextSibling {
			if c.Data == "b" {
				r.Name += c.FirstChild.Data
			} else if c.FirstChild == nil {
				r.Name += c.Data
			}
		}
		r.Size = htmlquery.FindOne(node, "//div/div/span[4]/b/text()").Data
		ret = append(ret, r)
	}

	return
}

func (p plugin) SearchKey(keyword string, page int64) (ret []search.Result) {

	v := make(url.Values)
	v.Add("keyword", keyword)
	v.Add("hidden", "true")

	resp, err := httpClient.PostForm(mainUrl, v)
	if err != nil {
		log.Println(err)
		return
	}
	defer resp.Body.Close()
	location := resp.Header.Get("location")
	if location == "" {
		log.Println("why")
		return
	}
	resp1, err := httpClient.Get(fmt.Sprintf("https:%s", strings.Replace(location, "/1/", fmt.Sprintf("/%v/", page), 1)))
	if err != nil {
		log.Println(err)
		return
	}
	defer resp1.Body.Close()

	if ret, err = parseRet(resp1.Body); err != nil {
		log.Println(err)
		return
	}
	return
}
