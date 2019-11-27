package main

import (
	"btplayer/search"
	"crypto/sha1"
	"encoding/base32"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"strconv"
	"sync"
	"time"

	"github.com/anacrolix/torrent"
	"github.com/anacrolix/torrent/metainfo"
	"github.com/gorilla/websocket"
	mgo "gopkg.in/mgo.v2"
	"gopkg.in/mgo.v2/bson"
)

type Config struct {
	DBUrl         string
	DBName        string
	CookieExpires time.Duration
	DownloadDir   string
}

type Torrent struct {
	T       *torrent.Torrent
	RefCnt  int
	HasInfo bool
}

var (
	session     *mgo.Session
	userColl    *mgo.Collection
	loginColl   *mgo.Collection
	torrentColl *mgo.Collection

	config Config

	tClient *torrent.Client
	Map     sync.Map
)

func checkLogin(req *http.Request) bool {
	id, err := req.Cookie("id")
	if err != nil {
		return false
	}
	name, err := req.Cookie("name")
	if err != nil {
		return false
	}
	if err := loginColl.Find(bson.M{"id": id.Value, "username": name.Value}).One(nil); err != nil {
		if err != mgo.ErrNotFound {
			log.Println(err)
		}
		return false
	}
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

	if !checkLogin(req) {
		statusCode = 403
		msg = "not login"
		return
	}

	if req.Method != "PUT" {
		statusCode = 405
		msg = "method not allow"
		return
	}

	infohash := req.URL.Query().Get("hash")
	t, err := tClient.AddMagnet(fmt.Sprintf("magnet:?xt=urn:btih:%s", infohash))
	if err != nil {
		log.Println(err)
		statusCode = 500
		return
	}
	if _, err := torrentColl.Upsert(bson.M{"_id": infohash}, bson.M{"_id": infohash}); err != nil {
		t.Drop()
		log.Println(err)
		statusCode = 500
		return
	}
	username, _ := req.Cookie("name")
	if err := userColl.Update(bson.M{"username": username.Value, "hashes": bson.M{"$nin": []string{infohash}}}, bson.M{"$push": bson.M{"hashes": infohash}}); err != nil {
		if err != mgo.ErrNotFound {
			log.Println(err)
			statusCode = 500
			return
		}
	}
}

func handleInfos(w http.ResponseWriter, req *http.Request) {
	var (
		ret struct {
			Hashes    []string `json:"hashes"`
			PageTotal int      `json:"pageTotal"`
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

	if !checkLogin(req) {
		statusCode, msg = 403, "not login"
		return
	}

	switch req.Method {
	case "GET":
		switch infoTypes := req.URL.Query().Get("type"); infoTypes {
		case "all":
		default:
			username, _ := req.Cookie("name")
			if err = userColl.Find(bson.M{"username": username.Value}).One(&ret); err != nil {
				log.Println(err)
				statusCode, msg = 500, "something goes wrong, please contacts administator"
				return
			}
			ret.PageTotal = len(ret.Hashes)
		}
		if jsonRet, err = json.Marshal(ret); err != nil {
			log.Println(err)
			statusCode, msg = 500, "something goes wrong, please contacts administator"
			return
		}

	case "DELETE":
		infohash := req.URL.Query().Get("hash")
		username, _ := req.Cookie("name")
		if err := userColl.Update(bson.M{"username": username.Value, "hashes": infohash}, bson.M{"$pull": bson.M{"hashes": infohash}}); err != nil {
			if err == mgo.ErrNotFound {
				statusCode, msg = 400, "fuck infohash"
				return
			}
			log.Println(err)
			statusCode, msg = 500, "sorry, you can't do that now, please retry"
			return
		}
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
		statusCode = 400
		msg = "have no this infohash"
		return
	}
	if t.Name() == "" {
		statusCode = 400
		msg = "have no files info"
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
	if !checkLogin(req) {
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

	for {
		var jsonData struct {
			Type string
			Data string
		}
		if err := c.ReadJSON(&jsonData); err != nil {
			log.Println(err)
			if websocket.IsCloseError(err, websocket.CloseGoingAway, websocket.CloseAbnormalClosure) {
				log.Println(c.Close())
				break
			}
			c.WriteMessage(0, []byte(`{"type": "error", "data": "sorry for that"}`))
			continue
		}
		if jsonData.Type == "info" {
			go processWsInfo(c, jsonData.Data)
		} else if jsonData.Type == "player" {
			go processWsPlayer(c, jsonData.Data)
		} else {
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

	if !checkLogin(req) {
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
	retJson, err = json.Marshal(ret)
	if err != nil {
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

		login struct {
			Username string
			Password string
			Id       string
		}
	)

	defer func() {
		if statusCode != 200 {
			w.Header().Set("X-Message", msg)
			w.WriteHeader(statusCode)
			return
		}
		if req.Method == "POST" {
			setCookie(w, "id", login.Id, "/", time.Now().Add(24*365*time.Hour))
			setCookie(w, "name", login.Username, "/", time.Now().Add(24*365*time.Hour))
		}
	}()

	//// check if login before
	if req.Method == "GET" {
		id, err := req.Cookie("id")
		if err != nil {
			statusCode, msg = 403, "not login"
			return
		}
		if err := loginColl.Update(bson.M{"id": id.Value}, bson.M{"$set": bson.M{"createAt": time.Now()}}); err != nil {
			if err == mgo.ErrNotFound {
				statusCode, msg = 403, "login expired"
				return
			}
			statusCode, msg = 500, "login status not avaiable"
			return
		}
		statusCode, msg = 200, "login status is ok"
		return
	}

	if err := req.ParseForm(); err != nil {
		statusCode = 400
		return
	}
	login.Username, login.Password = req.Form.Get("username"), req.Form.Get("password")
	if err := userColl.Find(bson.M{"username": login.Username, "password": login.Password}).One(nil); err != nil {
		if err == mgo.ErrNotFound {
			statusCode, msg = 403, "Wrong username or password"
			return
		}
		statusCode = 500
		log.Println(err.Error())
		return
	}

	login.Id = fmt.Sprintf("%x", sha1.Sum([]byte(login.Username+login.Password+time.Now().String())))
	if _, err := loginColl.Upsert(bson.M{"username": login.Username}, bson.M{"username": login.Username, "id": login.Id, "createAt": time.Now(), "ip": req.Header.Get("X-Real-IP")}); err != nil {
		log.Println(err)
		statusCode, msg = 500, "Something goes wrong, please contracts administator"
		return
	}
}

func handleLogout(w http.ResponseWriter, req *http.Request) {
	var (
		id, name   *http.Cookie
		msg        = "sb"
		statusCode = 403
		err        error
	)
	defer func() {
		w.Header().Set("X-Message", msg)
		w.WriteHeader(statusCode)
	}()

	if id, err = req.Cookie("id"); err != nil {
		log.Println(err)
		return
	}
	if name, err = req.Cookie("name"); err != nil {
		log.Println(err)
		return
	}
	if err := loginColl.Remove(bson.M{"username": name.Value, "id": id.Value}); err != nil {
		if err != mgo.ErrNotFound {
			log.Println(err)
			msg = "something goes wrong, please retry"
			statusCode = 500
		}
		return
	}
	statusCode, msg = 200, "ok"
}

func main() {
	var err error
	log.SetFlags(log.Lshortfile)

	// init config
	config.DBUrl = "127.0.0.1"
	config.DBName = "btplayer"
	config.CookieExpires = time.Hour * 24 * 30
	config.DownloadDir = "download"
	// end init config

	if session, err = mgo.Dial(config.DBUrl); err != nil {
		log.Fatal(err)
	}
	db := session.DB(config.DBName)
	userColl = db.C("user")
	loginColl = db.C("login")
	torrentColl = db.C("torrent")
	if err := loginColl.EnsureIndex(mgo.Index{Key: []string{"createdAt"}, ExpireAfter: config.CookieExpires}); err != nil {
		log.Fatal(err)
	}
	torrentColl.DropCollection()
	if err := os.RemoveAll(config.DownloadDir); err != nil && err != os.ErrNotExist {
		log.Fatal(err)
	}
	if err := os.Mkdir(config.DownloadDir, 0660); err != nil && err != os.ErrExist {
		log.Fatal(err)
	}
	tConfig := torrent.NewDefaultClientConfig()
	tConfig.DataDir = config.DownloadDir
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
