package main

import (
	"btplayer/search"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"time"

	"golang.org/x/net/html"

	"github.com/antchfx/xquery/html"
)

type plugin struct {
}

var mainUrl = "https://cnbtkitty.cc/"
var moduleName = "btkitty"
var httpClient = &http.Client{
	Timeout: 5 * time.Second,
}

func init() {
	search.Register(plugin{})
	log.Println(fmt.Sprintf("%v init ok.", moduleName))
}

func getInfoHash(node *html.Node) (infohash string) {
	if n := htmlquery.FindOne(node, "/html/body/div[1]/div[3]/div/dl/dd[2]"); n != nil {
		infohash = n.FirstChild.Data
	}
	return
}

func getName(node *html.Node) (name string) {
	if n := htmlquery.FindOne(node, "/html/body/div[1]/div[3]/div/dl/dd[1]"); n != nil {
		name = n.FirstChild.Data
	}
	return
}

func getSize(node *html.Node) (size string) {
	if n := htmlquery.FindOne(node, "/html/body/div[1]/div[3]/div/dl/dd[3]"); n != nil {
		size = n.FirstChild.Data
	}
	return
}

func getMagnet(node *html.Node) (magnet string) {
	if n := htmlquery.FindOne(node, "/html/body/div[1]/div[3]/div/dl/dd[10]/a"); n != nil {
		magnet = htmlquery.SelectAttr(n, "href")
	}
	return
}

func parseHtml(u string, ch chan<- search.Result) {
	ret := search.Result{}
	var doc *html.Node
	resp, err := httpClient.Get(u)
	if err != nil {
		log.Println(err)
		goto END
	}
	doc, err = htmlquery.Parse(resp.Body)
	if err != nil {
		log.Println(err)
		goto END
	}

	ret.Name = getName(doc)
	ret.Size = getSize(doc)
	ret.InfoHash = getInfoHash(doc)
	ret.Magnet = getMagnet(doc)

END:
	ch <- ret
	return
}

func parseRet(body io.ReadCloser) (ret []search.Result, err error) {
	doc, err := htmlquery.Parse(body)
	if err != nil {
		return
	}

	ch := make(chan search.Result, 20)
	nodes := htmlquery.Find(doc, "/html/body/div[1]/div[3]/div/dl")
	for _, node := range nodes {
		v := htmlquery.SelectAttr(htmlquery.FindOne(node, "//dt/a"), "href")
		go parseHtml(fmt.Sprintf("https:%v", v), ch)
	}

	for i := len(nodes); i > 0; i-- {
		select {
		case r := <-ch:
			if r.InfoHash != "" {
				ret = append(ret, r)
			}
		}
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

	ret, err = parseRet(resp.Body)
	if err != nil {
		log.Println(err)
	}
	return
}
