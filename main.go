package main

import (
	"btplayer/search"
	"crypto/sha1"
	"encoding/base32"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
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

type Torrent struct {
	T       *torrent.Torrent
	RefCnt  int
	HasInfo bool
}

var (
	session  *mgo.Session
	userColl *mgo.Collection

	tClient *torrent.Client
	file    io.ReadSeeker
	Map     sync.Map

	downloadDir string = "download"
)

func checkLogin(req *http.Request) bool {
	id, err := req.Cookie("id")
	if err != nil {
		return false
	}
	if err := userColl.Find(bson.M{"id": id.Value}).One(nil); err != nil {
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

func HandleAddMagnet(w http.ResponseWriter, req *http.Request) {
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
	infohash := req.URL.Query().Get("hash")
	if _, err := tClient.AddMagnet(fmt.Sprintf("magnet:?xt=urn:btih:%s", infohash)); err != nil {
		log.Println(err)
		statusCode = 500
		return
	}
}

func HandleFile(w http.ResponseWriter, req *http.Request) {
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

func handlePlayerClose(w http.ResponseWriter, req *http.Request) {
	c, err := newWebSocket(w, req, true)
	if err != nil {
		log.Println(err)
		return
	}
	defer c.Close()

	ch := make(chan struct{})
	c.SetCloseHandler(func(code int, text string) error {
		ch <- struct{}{}
		return nil
	})
	<-ch
}

func HandleWs(w http.ResponseWriter, req *http.Request) {
	// if !checkLogin(req) {
	// 	w.Header().Set("X-Message", "not login")
	// 	w.WriteHeader(403)
	// 	return
	// }
	c, err := newWebSocket(w, req, true)
	if err != nil {
		log.Println(err)
		return
	}
	defer c.Close()

	var info struct {
		InfoHash string   `json:"infohash"`
		Name     string   `json:"name"`
		Size     int64    `json:"size"`
		Files    []string `json:"files"`
	}

	_, msg, err := c.ReadMessage()
	if err != nil {
		log.Println(err)
		return
	}

	t, ok := getTorrent(msg)
	if !ok {
		log.Println("maybe have no this infohash")
		return
	}

	select {
	case <-t.GotInfo():
		info.Name = t.Name()
		info.InfoHash = t.InfoHash().String()
		info.Size = t.Info().TotalLength()
		for _, f := range t.Files() {
			info.Files = append(info.Files, f.Path())
		}
	}
	if err := c.WriteJSON(info); err != nil {
		log.Println(err)
		return
	}
}

func HandleSearch(w http.ResponseWriter, req *http.Request) {
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
			setCookie("id", login.Id, "/", time.Now().Add(24*365*time.Hour))
			setCookie("name", login.Username, "/", time.Now().Add(24*365*time.Hour))
		}
	}()

	//// check if login before
	if req.Method == "GET" {
		cookie, err := req.Cookie("id")
		if err != nil {
			statusCode, msg = 403, "login expired"
			return
		}
		if err := userColl.Find(bson.M{"id": cookie.Value}).One(nil); err == mgo.ErrNotFound {
			statusCode, msg = 403, "login expired"
			return
		}
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
	if err := userColl.Update(bson.M{"username": login.Username}, bson.M{"$set": bson.M{"id": login.Id, "last": time.Now().Unix(), "ip": req.Header.Get("X-Real-IP")}}); err != nil {
		log.Println(err)
		statusCode, msg = 500, "Something goes wrong, please contracts administator"
		return
	}
}

func handleLogout(w http.ResponseWriter, req *http.Request) {
	statusCode := 403
	msg := "sb"
	defer func() {
		w.Header().Set("X-Message", msg)
		w.WriteHeader(statusCode)
	}()

	id, err := req.Cookie("id")
	if err != nil {
		return
	}
	name, err := req.Cookie("name")
	if err != nil {
		return
	}
	if err := userColl.Update(bson.M{"username": name.Value, "id": id.Value}, bson.M{"$set": bson.M{"id": ""}}); err != nil {
		if err != mgo.ErrNotFound {
			msg = "something goes wrong, please retry"
			statusCode = 500
		}
		return
	}
	statusCode = 200
	msg = "ok"
}

func main() {
	var err error
	log.SetFlags(log.Lshortfile)

	search.Init()

	session, err = mgo.Dial("127.0.0.1")
	if err != nil {
		log.Fatal(err)
	}
	userColl = session.DB("btplayer").C("user")

	if err := os.RemoveAll(downloadDir); err != nil && err != os.ErrNotExist {
		log.Fatal(err)
	}
	if err := os.Mkdir(downloadDir, 0666); err != nil && err != os.ErrExist {
		log.Fatal(err)
	}
	config := torrent.NewDefaultClientConfig()
	config.DataDir = downloadDir
	if tClient, err = torrent.NewClient(config); err != nil {
		log.Fatal(err)
	}

	http.HandleFunc("/login", handleLogin)
	http.HandleFunc("/logout", handleLogout)
	http.HandleFunc("/info", HandleAddMagnet)
	http.HandleFunc("/search", HandleSearch)
	http.HandleFunc("/file", HandleFile)
	http.HandleFunc("/ws", HandleWs)
	http.ListenAndServe("127.0.0.1:8084", nil)
}
