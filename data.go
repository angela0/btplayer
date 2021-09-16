package main

import (
	"sync"
	"time"
)

type _UserData struct {
	Name string
	Time time.Time
}

// TODO: delete session after timeout
type Session struct {
	lock  sync.RWMutex
	table map[string]*_UserData
}

func NewSession() *Session {
	return &Session{
		table: make(map[string]*_UserData),
	}
}

func (s *Session) Add(name, id string) {
	now := time.Now()
	s.lock.Lock()
	defer s.lock.Unlock()
	s.table[id] = &_UserData{
		Name: name,
		Time: now,
	}
}

func (s *Session) Remove(id string) {
	s.lock.Lock()
	defer s.lock.Unlock()
	delete(s.table, id)
}

func (s *Session) Check(name, id string) bool {
	s.lock.Lock()
	defer s.lock.Unlock()

	user, ok := s.table[id]
	if !ok || user.Name != name {
		return false
	}
	user.Time = time.Now()

	return true
}

type _Set struct {
	lock sync.RWMutex
	set  map[string]struct{}
}

type Hash struct {
	lock  sync.RWMutex
	table map[string]*_Set
}

func NewHash() *Hash {
	return &Hash{
		table: make(map[string]*_Set),
	}
}

func (h *Hash) Add(name, infohash string) {
	h.lock.Lock()

	t, ok := h.table[name]
	if !ok {
		t = &_Set{set: make(map[string]struct{})}
		h.table[name] = t
	}
	h.lock.Unlock()

	t.lock.Lock()
	defer t.lock.Unlock()
	t.set[infohash] = struct{}{}
}

// TODO: remove empty hash user
func (h *Hash) Remove(name, infohash string) {
	h.lock.Lock()

	t, ok := h.table[name]
	h.lock.Unlock()
	if !ok {
		return
	}

	t.lock.Lock()
	defer t.lock.Unlock()
	delete(t.set, infohash)
}

func (h *Hash) All() []string {
	return nil
}

func (h *Hash) Get(user string) []string {
	h.lock.RLock()

	t, ok := h.table[user]
	h.lock.RUnlock()
	if !ok {
		return nil
	}

	t.lock.RLock()
	defer t.lock.RUnlock()

	ret := make([]string, len(t.set))
	var i int
	for k := range t.set {
		ret[i] = k
		i += 1
	}
	return ret
}

type Auth struct {
	lock  sync.RWMutex
	table map[string]*User
}

func NewAuth(users []*User) *Auth {
	auth := &Auth{
		table: make(map[string]*User),
	}
	for _, u := range users {
		auth.table[u.Name] = u
	}
	return auth
}

// for now, we may don't need lock
func (auth *Auth) DoAuth(name, password string) bool {
	user, ok := auth.table[name]
	return ok && user.Password == password
}
