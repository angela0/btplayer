package search

import (
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"strings"

	"github.com/antchfx/htmlquery"
)

type BTLibrary struct {
	Name string

	Url string

	HttpClient *http.Client
}

func (p *BTLibrary) parseRet(body io.ReadCloser) (ret []Result, err error) {
	doc, err := htmlquery.Parse(body)
	if err != nil {
		return
	}

	for _, node := range htmlquery.Find(doc, `//div[@class="item"]`) {
		r := Result{}
		a := htmlquery.FindOne(node, "//a")
		r.InfoHash = strings.Split(htmlquery.SelectAttr(a, "href"), "/")[2]
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

func (p *BTLibrary) SearchKey(keyword string, page int64) (ret []Result) {

	v := make(url.Values)
	v.Add("keyword", keyword)
	// v.Add("hidden", "true")

	host := "http://btlibrarycn.com"

	resp, err := p.HttpClient.PostForm(host, v)
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
	u, err := url.Parse(strings.Replace(fmt.Sprintf("%s%s", host, location), "/1/0/0", fmt.Sprintf("/%v/1/2", page), 1))
	if err != nil {
		log.Println(err)
		return
	}
	resp1, err := p.HttpClient.Get(u.String())
	if err != nil {
		log.Println(err)
		return
	}
	defer resp1.Body.Close()

	if ret, err = p.parseRet(resp1.Body); err != nil {
		log.Println(err)
		return
	}
	return
}
