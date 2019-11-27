package search

import "testing"

func TestSearch(t *testing.T) {
	t.Log(Search("chinese", 0))
	t.Log(Search("chinese", 1))
}
