package search

import (
	"fmt"
	"log"
	"plugin"
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

var searchPlugin = struct {
	Path    string
	Plugins []string
}{
	"search/plugins",
	[]string{"btlibrary"},
}

var plugins []SearchType

func Init() {
	for _, v := range searchPlugin.Plugins {
		if _, err := plugin.Open(fmt.Sprintf("%s/%s/%s.so", searchPlugin.Path, v, v)); err != nil {
			log.Fatal(err)
		}
	}
}

func Register(p SearchType) {
	plugins = append(plugins, p)
}

func Search(keyword string, page int64) (ret []Result) {
	for _, p := range plugins {
		ret = append(ret, p.SearchKey(keyword, page)...)
	}
	return
}
