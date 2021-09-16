package utils

import "net/url"

func GetOrDefault(q url.Values, k, d string) string {
	v := q.Get(k)
	if v != "" {
		d = v
	}
	return d
}
