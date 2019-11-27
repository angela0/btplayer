package search

import (
	"net/http"
	"time"
)

type Result struct {
	InfoHash string   `json:"infohash"`
	Name     string   `json:"name"`
	Size     string   `json:"size"`
	Magnet   string   `json:"magnet"`
	Files    []string `json:"files"`
	Thumb    string   `json:"thumb"`
}

type SearchType interface {
	SearchKey(string, int64) []Result
}

var searchPlugin = []string{
	"idope",
	"btlibrary",
}

var plugins []SearchType

func init() {
	plugins = append(plugins,
		&Idope{
			Name:       "idope",
			HttpClient: http.DefaultClient,
		},
		&BTLibrary{
			Name: "btlibrary",
			HttpClient: &http.Client{
				Timeout: 5 * time.Second,
				CheckRedirect: func(req *http.Request, via []*http.Request) error {
					return http.ErrUseLastResponse
				},
			},
		},
	)
}

func Search(keyword string, page int64) (ret []Result) {
	for _, p := range plugins {
		ret = append(ret, p.SearchKey(keyword, page)...)
	}
	return
}
