package tokbox

import (
	"net/http"
	"net/url"

	"encoding/json"

	"fmt"
	"strings"
	"time"

	"golang.org/x/net/context"

	jwt "github.com/dgrijalva/jwt-go"
	"github.com/myesui/uuid"
)

const (
	apiHost    = "https://api.opentok.com"
	apiSession = "/session/create"
)

const (
	// Days30 represents 30 days duration in seconds
	Days30 = 2592000 //30 * 24 * 60 * 60

	// Weeks1 represents one week duration in seconds
	Weeks1 = 604800 //7 * 24 * 60 * 60

	// Hours24 represents 24 hours duration in seconds
	Hours24 = 86400 //24 * 60 * 60

	// Hours2 represents 2 hours duration in seconds
	Hours2 = 7200 //60 * 60 * 2

	// Hours1 represents 1 hour duration in seconds
	Hours1 = 3600 //60 * 60
)

// MediaMode type - https://tokbox.com/developer/guides/create-session/#media-mode
type MediaMode string

const (
	// MediaRouter specifies the media mode to stream via the OpenTok Media Router
	MediaRouter MediaMode = "disabled"
	// P2P specifies the media mode to stream directly between clients. If clients cannot connect
	// due to firewall restrictions, the session uses the OpenTok TURN server to relay streams.
	P2P MediaMode = "enabled"
)

// String returns the string value of a MediaMode instance
func (i MediaMode) String() string {
	return string(i)
}

// ArchiveMode type - https://tokbox.com/developer/rest/#session_id_production
type ArchiveMode string

const (
	// ArchiveModeManual allows the session to be archived manually but starts the session without archiving
	// This is the default behavior
	ArchiveModeManual ArchiveMode = "manual"
	// ArchiveModeAlways automatically archive the session - https://tokbox.com/developer/guides/archiving/#automatic
	ArchiveModeAlways ArchiveMode = "always"
)

// String returns the string value of a MediaMode instance
func (i ArchiveMode) String() string {
	return string(i)
}

// Tokbox struct represents the REST API abstraction as a library
type Tokbox struct {
	apiKey        string
	partnerSecret string

	// BetaURL should be used to override the base url by the url from thee beta program.
	BetaURL string
}

// CreateSessionRequest provides all information needed by a session to be created
type CreateSessionRequest struct {
	Location    string
	MediaMode   MediaMode
	ArchiveMode ArchiveMode
}

// New returns a new instance of Tokbox
func New(apikey, partnerSecret string) *Tokbox {
	return &Tokbox{apikey, partnerSecret, ""}
}

// CreateSession creates a new tokbox session or returns an error.
// See README file for full documentation: https://github.com/pjebs/tokbox
// NOTE: ctx must be nil if *not* using Google App Engine
func (t *Tokbox) CreateSession(req *CreateSessionRequest, ctx ...context.Context) (*Session, error) {
	params := url.Values{}

	if len(req.Location) > 0 {
		params.Add("location", req.Location)
	}

	p2pPreference := P2P
	if len(req.MediaMode) > 0 {
		p2pPreference = req.MediaMode
	}
	params.Add("p2p.preference", p2pPreference.String())

	if len(req.ArchiveMode) > 0 {
		params.Add("archiveMode", req.ArchiveMode.String())
	}

	body := strings.NewReader(params.Encode())
	r, err := http.NewRequest("POST", t.endpoint()+apiSession, body)
	if err != nil {
		return nil, err
	}

	//Create jwt token
	jwt, err := t.jwtToken()
	if err != nil {
		return nil, err
	}

	r.Header.Add("Accept", "application/json")
	r.Header.Add("X-OPENTOK-AUTH", jwt)

	if len(ctx) == 0 {
		ctx = append(ctx, nil)
	}
	res, err := client(ctx[0]).Do(r)
	if err != nil {
		return nil, err
	}
	defer res.Body.Close()

	if res.StatusCode != 200 {
		return nil, fmt.Errorf("Tokbox returns error code: %v", res.StatusCode)
	}

	var s []Session
	if err = json.NewDecoder(res.Body).Decode(&s); err != nil {
		return nil, err
	}

	if len(s) < 1 {
		return nil, fmt.Errorf("Tokbox did not return a session")
	}

	o := s[0]
	o.T = t
	return &o, nil
}

func (t *Tokbox) jwtToken() (string, error) {

	type TokboxClaims struct {
		Ist string `json:"ist,omitempty"`
		jwt.StandardClaims
	}

	claims := TokboxClaims{
		"project",
		jwt.StandardClaims{
			Issuer:    t.apiKey,
			IssuedAt:  time.Now().UTC().Unix(),
			ExpiresAt: time.Now().UTC().Unix() + (2 * 24 * 60 * 60), // 2 hours; //NB: The maximum allowed expiration time range is 5 minutes.
			Id:        uuid.NewV4().String(),
		},
	}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	return token.SignedString([]byte(t.partnerSecret))
}

func (t *Tokbox) endpoint() string {
	if t.BetaURL == "" {
		return apiHost
	}
	return t.BetaURL
}
