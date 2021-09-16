package main

import (
	"btplayer/search"
	"btplayer/utils"
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
	"time"

	"github.com/anacrolix/torrent"
	"github.com/anacrolix/torrent/metainfo"
	"github.com/gorilla/websocket"
)

type User struct {
	Name     string
	Password string
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
	config Config
	// must init session befere start http
	session *Session
	// must init authTable befere start http
	authTable *Auth
	// must init hashTable befere start http
	hashTable *Hash

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
	if id == "" || name == "" {
		return false
	}

	return session.Check(name, id)
}

func getTorrent(hashinfo string) (*torrent.Torrent, bool) {
	hash := []byte(hashinfo)
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

		hashTable.Add(name, infohash)
		return
	}
	if req.Method == "DELETE" {
		infohash := req.URL.Query().Get("hash")
		if t, ok := getTorrent(infohash); ok {
			t.Drop()
			t.DisallowDataUpload()
			os.RemoveAll(path.Join(config.DLDir, t.Info().Name))
		}

		hashTable.Remove(name, infohash)
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
		hashes := hashTable.Get(name)

		ret.Hashes = make([]struct {
			Hash string `json:"hash"`
			Name string `json:"name"`
		}, len(hashes))

		for i, k := range ret.Hashes {
			ret.Hashes[i].Hash = hashes[i]
			t, ok := getTorrent(k.Hash)
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
	statusCode, msg := 400, "bad request"

	defer func() {
		// if ok, then http.ServeContent will do all things
		if statusCode != 200 {
			w.Header().Set("X-Message", msg)
			w.WriteHeader(statusCode)
		}
	}()

	infohash, index := req.URL.Query().Get("hash"), req.URL.Query().Get("index")
	if infohash == "" || index == "" {
		return
	}
	indexInt, err := strconv.ParseInt(index, 10, 32)
	if err != nil {
		statusCode, msg = 400, "bad index"
		return
	}

	t, ok := getTorrent(infohash)
	if !ok {
		statusCode, msg = 404, "have no this infohash"
		return
	}
	if t.Name() == "" {
		statusCode, msg = 404, "have no files info"
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

func wsGetHashInfo(c *websocket.Conn, infohash string) {
	t, ok := getTorrent(infohash)
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

// func processWsPlayer(c *websocket.Conn, data string) {

// }

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
			go wsGetHashInfo(c, jsonData.Data)
		case "player":
			// go processWsPlayer(c, jsonData.Data)
		default:
			c.WriteMessage(0, []byte(`{"type": "error", "data": "fuck you"}`))
		}
	}
}

func handleSearch(w http.ResponseWriter, req *http.Request) {
	var (
		statusCode, msg = 200, "ok"
		ret             struct {
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
		statusCode, msg = 403, "not login"
		return
	}

	keyword := utils.GetOrDefault(req.URL.Query(), "keywork", "chinese")
	page := utils.GetOrDefault(req.URL.Query(), "page", "1")

	pageInt, err := strconv.ParseInt(page, 10, 64)
	if err != nil {
		log.Println(err)
		statusCode, msg = 400, "bad page"
	}
	ret.Results = search.Search(keyword, pageInt)
	if retJson, err = json.Marshal(ret); err != nil {
		log.Println(err)
		statusCode, msg = 500, "internal error"
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
		statusCode, msg = 200, "Login failed, so sorry"
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
	if !authTable.DoAuth(name, password) {
		statusCode = 403
		return
	}

	id = fmt.Sprintf("%x", sha1.Sum([]byte(name+password+time.Now().String())))

	session.Add(name, id)
}

func handleLogout(w http.ResponseWriter, req *http.Request) {
	var (
		statusCode, msg = 403, "sb"
	)
	defer func() {
		w.Header().Set("X-Message", msg)
		w.WriteHeader(statusCode)
	}()

	id, name := getAuth(req)
	if !checkLogin(id, name) {
		return
	}

	session.Remove(id)

	statusCode, msg = 200, "ok"
}

func initTorrent() (err error) {
	if err = os.RemoveAll(config.DLDir); err != nil && err != os.ErrNotExist {
		return
	}
	if err = os.Mkdir(config.DLDir, 0660); err != nil && err != os.ErrExist {
		return
	}

	tConfig := torrent.NewDefaultClientConfig()
	tConfig.DataDir = config.DLDir
	tClient, err = torrent.NewClient(tConfig)

	return
}

func initHttp() (err error) {
	http.HandleFunc("/login", handleLogin)
	http.HandleFunc("/logout", handleLogout)
	http.HandleFunc("/info", handleInfo)
	http.HandleFunc("/infos", handleInfos)
	http.HandleFunc("/search", handleSearch)
	http.HandleFunc("/file", handleFile)
	http.HandleFunc("/ws", handleWs)
	return http.ListenAndServe("127.0.0.1:8084", nil)
}

func initConfig() (err error) {
	f, err := ioutil.ReadFile(*configFile)
	if err != nil {
		return
	}
	return json.Unmarshal(f, &config)
}

var (
	configFile = flag.String("c", "config.json", "-c <config file>")
)

func main() {
	log.SetFlags(log.Lshortfile)
	flag.Parse()

	if err := initConfig(); err != nil {
		log.Fatal(err)
	}

	if err := initTorrent(); err != nil {
		log.Fatal(err)
	}

	authTable = NewAuth(config.Users)
	session = NewSession()
	hashTable = NewHash()

	if err := initHttp(); err != nil {
		log.Fatal(err)
	}
}
