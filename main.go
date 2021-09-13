package main

import (
	"btplayer/search"
	"crypto/sha1"
	"encoding/base32"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"os"
	"path"
	"strconv"
	"sync"
	"time"

	"github.com/anacrolix/torrent"
	"github.com/anacrolix/torrent/metainfo"
	"github.com/gorilla/websocket"
)

type User struct {
	Name     string
	Password string
}

type UserData struct {
	User
	ID     string              `json:"-"`
	Time   time.Time           `json:"-"`
	Hashes map[string]struct{} `json:"-"`
}

type Session struct {
	lock  sync.RWMutex
	table map[string]*UserData
}

type Hash struct {
	lock  sync.RWMutex
	table map[string]map[string]struct{}
}

type Config struct {
	Expires time.Duration `json:"expires"`
	DLDir   string        `json:"location"`
	Users   []*User       `json:"user"`
}

type Torrent struct {
	T       *torrent.Torrent
	RefCnt  int
	HasInfo bool
}

var (
	config    Config
	session   = &Session{table: make(map[string]*UserData)}
	authTable = make(map[string]*User)
	hashTable = make(map[string]map[string]struct{})

	tClient *torrent.Client
)

func getCookie(req *http.Request, key string) string {
	v, err := req.Cookie(key)
	if err != nil {
		return ""
	}
	return v.Value
}

func getAuth(req *http.Request) (string, string) {
	return getCookie(req, "id"), getCookie(req, "name")
}

func checkLogin(id, name string) bool {
	session.lock.Lock()
	defer session.lock.Unlock()

	if id == "" || name == "" {
		return false
	}
	user, ok := session.table[name]
	if !ok || user.ID != id {
		return false
	}
	user.Time = time.Now()
	return true
}

func getTorrent(hash []byte) (*torrent.Torrent, bool) {
	h := metainfo.Hash{}
	if len(hash) == 40 {
		hex.Decode(h[:], hash)
	} else {
		base32.StdEncoding.Decode(h[:], hash)
	}
	return tClient.Torrent(h)
}

func handleInfo(w http.ResponseWriter, req *http.Request) {
	statusCode, msg := 200, "add failed"

	defer func() {
		w.Header().Set("X-Message", msg)
		w.WriteHeader(statusCode)
	}()

	id, name := getAuth(req)
	if !checkLogin(id, name) {
		statusCode, msg = 403, "not login"
		return
	}

	infohash := req.URL.Query().Get("hash")
	if infohash == "" {
		statusCode, msg = 404, "wrong request"
		return
	}

	if req.Method == "PUT" {
		if _, err := tClient.AddMagnet(fmt.Sprintf("magnet:?xt=urn:btih:%s", infohash)); err != nil {
			log.Println(err)
			statusCode = 500
			return
		}

		session.lock.Lock()
		defer session.lock.Unlock()

		session.table[name].Hashes[infohash] = struct{}{}
		return
	}
	if req.Method == "DELETE" {
		infohash := req.URL.Query().Get("hash")
		if t, ok := getTorrent([]byte(infohash)); ok {
			t.Drop()
			t.DisallowDataUpload()
			os.RemoveAll(path.Join(config.DLDir, t.Info().Name))
		}

		session.lock.Lock()
		defer session.lock.Unlock()
		delete(session.table[name].Hashes, infohash)
		return
	}

	statusCode, msg = 405, "method not allow"
}

func handleInfos(w http.ResponseWriter, req *http.Request) {
	var (
		ret struct {
			Hashes []struct {
				Hash string `json:"hash"`
				Name string `json:"name"`
			} `json:"hashes"`
			PageTotal int `json:"pageTotal"`
		}
		jsonRet    []byte
		err        error
		statusCode = 200
		msg        = "bad request"
	)

	defer func() {
		w.Header().Set("X-Message", msg)
		w.WriteHeader(statusCode)
		if req.Method == "GET" {
			w.Write(jsonRet)
		}
	}()

	id, name := getAuth(req)
	if !checkLogin(id, name) {
		statusCode, msg = 403, "not login"
		return
	}

	switch req.URL.Query().Get("type") {
	case "all":
		//TODO: impl all
	default:
		session.lock.Lock()
		hashes := session.table[name].Hashes
		ret.Hashes = make([]struct {
			Hash string `json:"hash"`
			Name string `json:"name"`
		}, len(hashes))

		var i int
		for k := range hashes {
			ret.Hashes[i].Hash = k
			i += 1
		}

		session.lock.Unlock()

		for i, k := range ret.Hashes {
			t, ok := getTorrent([]byte(k.Hash))
			if !ok {
				continue
			}
			ret.Hashes[i].Name = t.Name()
		}

		ret.PageTotal = len(ret.Hashes)
	}

	if jsonRet, err = json.Marshal(ret); err != nil {
		log.Println(err)
		statusCode, msg = 500, "something goes wrong, please contacts administator"
		return
	}
}

func handleFile(w http.ResponseWriter, req *http.Request) {
	statusCode, msg := 200, "bad request"

	defer func() {
		// if ok, then http.ServeContent will do all things
		if statusCode != 200 {
			w.Header().Set("X-Message", msg)
			w.WriteHeader(statusCode)
		}
	}()

	infohash, index := req.URL.Query().Get("hash"), req.URL.Query().Get("index")
	if infohash == "" || index == "" {
		statusCode = 400
		return
	}
	indexInt, err := strconv.ParseInt(index, 10, 32)
	if err != nil {
		statusCode = 400
		msg = "bad index"
	}

	t, ok := getTorrent([]byte(infohash))
	if !ok {
		statusCode, msg = 400, "have no this infohash"
		return
	}
	if t.Name() == "" {
		statusCode, msg = 400, "have no files info"
		return
	}
	file := t.Files()[indexInt]
	file.Download()

	http.ServeContent(w, req, "", time.Now(), file.NewReader())
}

func newWebSocket(w http.ResponseWriter, req *http.Request, cros bool) (*websocket.Conn, error) {
	upgrader := websocket.Upgrader{}
	if cros {
		upgrader.CheckOrigin = func(*http.Request) bool {
			return true
		}
	}
	return upgrader.Upgrade(w, req, nil)
}

func processWsInfo(c *websocket.Conn, data string) {
	t, ok := getTorrent([]byte(data))
	if !ok {
		log.Println("maybe have no this infohash")
		return
	}

	var info struct {
		Type string `json:"type"`
		Data struct {
			InfoHash string   `json:"infohash"`
			Name     string   `json:"name"`
			Size     int64    `json:"size"`
			Files    []string `json:"files"`
		} `json:"data"`
	}
	select {
	case <-t.GotInfo():
		info.Type = "info"
		info.Data.Name = t.Name()
		info.Data.InfoHash = t.InfoHash().String()
		info.Data.Size = t.Info().TotalLength()
		for _, f := range t.Files() {
			info.Data.Files = append(info.Data.Files, f.Path())
		}
	}
	if err := c.WriteJSON(info); err != nil {
		log.Println(err)
		return
	}
}
func processWsPlayer(c *websocket.Conn, data string) {

}
func handleWs(w http.ResponseWriter, req *http.Request) {
	if !checkLogin(getAuth(req)) {
		w.Header().Set("X-Message", "not login")
		w.WriteHeader(403)
		return
	}
	c, err := newWebSocket(w, req, true)
	if err != nil {
		log.Println(err)
		return
	}
	defer c.Close()

	ticker := time.NewTicker(16 * time.Second)
	tickerCh := make(chan bool)
	defer func() {
		ticker.Stop()
		close(tickerCh)
	}()
	go func() {
		for {
			select {
			case <-ticker.C:
				c.WriteMessage(websocket.TextMessage, []byte(`{"type": "ping"}`))
			case <-tickerCh:
				return
			}
		}
	}()

	for {
		var jsonData struct {
			Type string
			Data string
		}
		if err := c.ReadJSON(&jsonData); err != nil {
			if websocket.IsCloseError(err, websocket.CloseGoingAway, websocket.CloseAbnormalClosure) {
				c.Close()
				break
			}
			c.WriteMessage(0, []byte(`{"type": "error", "data": "sorry for that"}`))
			continue
		}
		switch jsonData.Type {
		case "info":
			go processWsInfo(c, jsonData.Data)
		case "player":
			go processWsPlayer(c, jsonData.Data)
		default:
			c.WriteMessage(0, []byte(`{"type": "error", "data": "fuck you"}`))
		}
	}
}

func handleSearch(w http.ResponseWriter, req *http.Request) {
	var (
		msg        = "ok"
		statusCode = 200
		ret        struct {
			Results []search.Result `json:"results"`
		}
		retJson []byte
	)

	defer func() {
		if statusCode != 200 {
			w.Header().Set("X-Message", msg)
			w.WriteHeader(statusCode)
			return
		}
		w.Write(retJson)
	}()

	if !checkLogin(getAuth(req)) {
		statusCode = 403
		msg = "not login"
		return
	}

	q := req.URL.Query()
	keyword, page := q.Get("keyword"), q.Get("page")
	if keyword == "" {
		keyword = "chinese"
	}
	if page == "" {
		page = "1"
	}
	pageInt, err := strconv.ParseInt(page, 10, 64)
	if err != nil {
		log.Println(err)
		msg = "bad page"
		statusCode = 400
	}
	ret.Results = search.Search(keyword, pageInt)
	if retJson, err = json.Marshal(ret); err != nil {
		log.Println(err)
		msg = "internal error"
		statusCode = 500
		return
	}
}

func setCookie(w http.ResponseWriter, name, value, path string, expires time.Time) {
	http.SetCookie(w, &http.Cookie{
		Name:    name,
		Value:   value,
		Path:    path,
		Expires: expires,
	})
}

func handleLogin(w http.ResponseWriter, req *http.Request) {
	var (
		statusCode = 200
		msg        = "Login failed, so sorry"
	)

	id, name := getAuth(req)

	defer func() {
		if statusCode != 200 {
			w.Header().Set("X-Message", msg)
			w.WriteHeader(statusCode)
			return
		}
		if req.Method == "POST" {
			setCookie(w, "id", id, "/", time.Now().Add(time.Second*config.Expires))
			setCookie(w, "name", name, "/", time.Now().Add(time.Second*config.Expires))
		}
	}()

	// check login status
	if req.Method == "GET" {
		if !checkLogin(id, name) {
			statusCode, msg = 403, "not login"
			return
		}
		statusCode, msg = 200, "login status is ok"
		return
	}

	if err := req.ParseForm(); err != nil {
		statusCode = 400
		return
	}
	name, password := req.Form.Get("username"), req.Form.Get("password")
	user, ok := authTable[name]
	if !ok || user.Password != password {
		statusCode = 403
		return
	}
	session.lock.Lock()
	defer session.lock.Unlock()
	userdata, ok := session.table[name]
	if ok {
		id = userdata.ID
		return
	}

	id = fmt.Sprintf("%x", sha1.Sum([]byte(name+password+time.Now().String())))
	session.table[name] = &UserData{
		User: User{
			Name:     name,
			Password: password,
		},
		ID:     id,
		Time:   time.Now(),
		Hashes: make(map[string]struct{}),
	}
}

func handleLogout(w http.ResponseWriter, req *http.Request) {
	var (
		msg        = "sb"
		statusCode = 403
	)
	defer func() {
		w.Header().Set("X-Message", msg)
		w.WriteHeader(statusCode)
	}()

	id, name := getAuth(req)
	if !checkLogin(id, name) {
		return
	}

	session.lock.Lock()
	defer session.lock.Unlock()
	delete(session.table, name)

	statusCode, msg = 200, "ok"
}

var (
	configFile = flag.String("c", "config.json", "-c <config file>")
)

func main() {
	var err error
	log.SetFlags(log.Lshortfile)

	flag.Parse()

	f, err := ioutil.ReadFile(*configFile)
	if err != nil {
		log.Fatal(err)
	}
	if err = json.Unmarshal(f, &config); err != nil {
		log.Fatal(err)
	}

	for _, u := range config.Users {
		authTable[u.Name] = u
	}

	if err := os.RemoveAll(config.DLDir); err != nil && err != os.ErrNotExist {
		log.Fatal(err)
	}
	if err := os.Mkdir(config.DLDir, 0660); err != nil && err != os.ErrExist {
		log.Fatal(err)
	}

	tConfig := torrent.NewDefaultClientConfig()
	tConfig.DataDir = config.DLDir
	if tClient, err = torrent.NewClient(tConfig); err != nil {
		log.Fatal(err)
	}

	http.HandleFunc("/login", handleLogin)
	http.HandleFunc("/logout", handleLogout)
	http.HandleFunc("/info", handleInfo)
	http.HandleFunc("/infos", handleInfos)
	http.HandleFunc("/search", handleSearch)
	http.HandleFunc("/file", handleFile)
	http.HandleFunc("/ws", handleWs)
	http.ListenAndServe("127.0.0.1:8084", nil)
}
