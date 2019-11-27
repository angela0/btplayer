package search

import (
	"fmt"
	"io"
	"log"
	"net/http"
	"strings"

	"golang.org/x/net/html"

	htmlquery "github.com/antchfx/xquery/html"
)

type Idope struct {
	// useless now
	Name string

	// default use http.DefaultClient
	HttpClient *http.Client
}

var searchUrl = "https://idope.se/torrent-list/"

func getInfoHash(node *html.Node) (infohash string) {
	if segs := strings.Split(htmlquery.SelectAttr(node, "href"), "/"); len(segs) == 5 {
		infohash = segs[3]
	}
	return
}

func getName(node *html.Node) (name string) {
	if div := htmlquery.FindOne(node, `//div/div[1]/div`); div != nil && div.FirstChild != nil {
		name = strings.Trim(div.FirstChild.Data, "")
	}
	return
}

func getSize(node *html.Node) (size string) {
	if div := htmlquery.FindOne(node, `//div/div[2]/div[2]/div`); div != nil && div.FirstChild != nil {
		size = strings.Trim(div.FirstChild.Data, "")
	}
	return
}

func (p *Idope) parseRet(body io.ReadCloser) (ret []Result, err error) {
	doc, err := htmlquery.Parse(body)
	if err != nil {
		return
	}

	nodes := htmlquery.Find(doc, `//*[@id="div2"]/a`)
	for _, node := range nodes {
		r := Result{
			InfoHash: getInfoHash(node),
			Name:     getName(node),
			Size:     getSize(node),
		}

		if r.InfoHash != "" {
			ret = append(ret, r)
		}
	}

	return
}

func (p *Idope) SearchKey(keyword string, page int64) (ret []Result) {
	resp, err := p.HttpClient.Get(fmt.Sprintf("%s%s/?p=%v", searchUrl, keyword, page))
	if err != nil {
		log.Println(err)
		return
	}
	defer resp.Body.Close()

	ret, err = p.parseRet(resp.Body)
	if err != nil {
		log.Println(err)
	}
	return
}
