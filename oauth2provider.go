package oauth2provider

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"

	"github.com/credli/osin"
	"github.com/gorilla/mux"

	"golang.org/x/crypto/bcrypt"
	"golang.org/x/net/context"
	"google.golang.org/appengine"
	"google.golang.org/appengine/log"
	"google.golang.org/appengine/urlfetch"
)

type AEServer struct {
	sconfig *osin.ServerConfig
	server  *osin.Server
	storage osin.Storage
	AACJWT  AccessTokenGenJWT
}

func NewServer() *AEServer {
	s := &AEServer{sconfig: osin.NewServerConfig()}

	s.sconfig.AllowedAuthorizeTypes = osin.AllowedAuthorizeType{osin.CODE, osin.TOKEN}
	s.sconfig.AllowedAccessTypes = osin.AllowedAccessType{
		osin.AUTHORIZATION_CODE,
		osin.REFRESH_TOKEN,
		osin.PASSWORD,
		osin.CLIENT_CREDENTIALS}
	s.sconfig.AllowGetAccessRequest = true
	s.sconfig.AllowClientSecretInParams = true
	s.storage = NewAEStorage()
	s.server = osin.NewServer(s.sconfig, s.storage)
	AACJWT := &AccessTokenGenJWT{privatekey, publickey}
	s.server.AccessTokenGen = AACJWT
	return s
}

func init() {
	server := NewServer()
	r := mux.NewRouter()
	r.HandleFunc("/init", server.HandleInitClient)
	r.HandleFunc("/authorize", server.HandleAuthorize)
	r.HandleFunc("/token", server.HandleToken)

	// r.HandleFunc("/app", HandleApp)
	// r.HandleFunc("/appauth/code", HandleAppAuthCode)
	// r.HandleFunc("/appauth/client_credentials", HandleAppAuthClientCredentials)
	r.HandleFunc("/appauth/password", server.HandleAppAuthPassword)
	r.HandleFunc("/appauth/info", server.HandleInfo)
	r.HandleFunc("/appauth/refresh", server.HandleAppAuthRefresh)
	// r.HandleFunc("/appauth/info", server.HandleAppAuthInfo)
	http.Handle("/", r)
}

//HandleAuthorize handles implicit authorization
//USAGE:http://localhost:8080/authorize?response_type=token&client_id=47bef51d-1b4a-4028-b4a1-07dfe3116a9b&state=xyz&scope=everything
func (s *AEServer) HandleAuthorize(w http.ResponseWriter, r *http.Request) {
	c := appengine.NewContext(r)
	resp := s.server.NewResponse()
	defer resp.Close()

	if ar := s.server.HandleAuthorizeRequest(c, resp, r); ar != nil {
		ar.Authorized = true
		s.server.FinishAuthorizeRequest(c, resp, r, ar)
	}
	if resp.IsError && resp.InternalError != nil {
		log.Errorf(c, "%v", resp.InternalError)
	}
	if !resp.IsError {
		resp.Output["custom_parameter"] = 4567890567
	}
	log.Infof(c, "AUTHORIZED")
	osin.OutputJSON(resp, w, r)
}

func (s *AEServer) HandleInitClient(w http.ResponseWriter, r *http.Request) {
	c := appengine.NewContext(r)

	client := &ClientModel{
		"47bef51d-1b4a-4028-b4a1-07dfe3116a9b",
		"Paperplane Auth",
		"http://localhost:14000/appauth",
		true,
		"password",
		"aabbccdd",
	}
	s.insertClient(c, client)
}

func (s *AEServer) HandleToken(w http.ResponseWriter, r *http.Request) {
	c := appengine.NewContext(r)
	log.Infof(c, "HANDLE TOKEN")
	resp := s.server.NewResponse()
	defer resp.Close()
	if ar := s.server.HandleAccessRequest(c, resp, r); ar != nil {
		switch ar.Type {
		case osin.IMPLICIT:
			log.Infof(c, "Passing through IMPLICIT %v", ar)
			ar.Authorized = true
		case osin.AUTHORIZATION_CODE:
			log.Infof(c, "Passing through CODE %v", ar)
			ar.Authorized = true
		case osin.REFRESH_TOKEN:
			ar.Authorized = true
		case osin.PASSWORD:
			log.Infof(c, "VERIFYING PASSWORD")
			if err := s.verifyPassword(c, ar.Username, ar.Password); err == nil {
				// var cl PPClient
				// cl = ar.Client.(PPClient)
				ar.Authorized = true
			}
		case osin.CLIENT_CREDENTIALS:
			ar.Authorized = true
		}
		s.server.FinishAccessRequest(c, resp, r, ar)
	}
	if resp.IsError && resp.InternalError != nil {
		log.Errorf(c, "%v", resp.InternalError)
	}
	if !resp.IsError {
		resp.Output["custom_parameter"] = 236663
	}
	osin.OutputJSON(resp, w, r)
}

func (s *AEServer) verifyPassword(c context.Context, username, password string) error {
	user, err := s.GetUser(c, username)
	if err != nil {
		log.Infof(c, "USER NOT FOUND")
		return err
	}
	err = bcrypt.CompareHashAndPassword([]byte(user.PasswordHash), []byte(password))
	if err != nil {
		return err
	}
	return nil
}

//HandleInfo handles password authentication
//USAGE: http://localhost:8080/appauth/info?grant_type=password&scope=everything&username=test&password=test
func (s *AEServer) HandleInfo(w http.ResponseWriter, r *http.Request) {
	c := appengine.NewContext(r)
	resp := s.server.NewResponse()
	defer resp.Close()

	if ir := s.server.HandleInfoRequest(c, resp, r); ir != nil {
		s.server.FinishInfoRequest(c, resp, r, ir)
		if err := s.AACJWT.VerToken(ir.AccessData.AccessToken); err != nil {
			log.Infof(c, err.Error())
		}
	}
	osin.OutputJSON(resp, w, r)
}

func HandleAppAuthToken(w http.ResponseWriter, r *http.Request) {
	r.ParseForm()

	w.Write([]byte("<html><body>"))
	w.Write([]byte("APP AUTH - TOKEN<br/>"))

	w.Write([]byte("Response data in fragment - not acessible via server - Nothing to do"))

	w.Write([]byte("</body></html>"))
}

//HandleAppAuthPassword handles password authentication
//USAGE: http://localhost:8080/appauth?grant_type=password&scope=everything&username=test&password=test
func (s *AEServer) HandleAppAuthPassword(w http.ResponseWriter, r *http.Request) {
	r.ParseForm()
	c := appengine.NewContext(r)
	switch r.Method {

	case "POST":

		//provide tls encryption over connection
		u := r.FormValue("username")
		p := r.FormValue("password")
		log.Infof(c, "HANDLE PASSWORD")
		jr := make(map[string]interface{})

		// build access code url
		aurl := fmt.Sprintf("/token?grant_type=password&scope=everything&username=%s&password=%s", u, p)

		err := downloadAccessToken(c, fmt.Sprintf("http://localhost:8081%s", aurl), &osin.BasicAuth{
			Username: "47bef51d-1b4a-4028-b4a1-07dfe3116a9b", Password: "aabbccdd"}, jr) //Password must be encrypted and stored in GCS

		if err != nil {
			b, err := json.Marshal(jr)
			if err == nil {

				fmt.Fprintf(w, "%s", b)
			}
		}

		// show json error
		if _, ok := jr["error"]; ok {
			b, err := json.Marshal(jr)
			if err == nil {
				fmt.Fprintf(w, "%s", b)
			}
		}

		// show json access token
		if _, ok := jr["access_token"]; ok {
			b, err := json.Marshal(jr)
			if err == nil {
				fmt.Fprintf(w, "%s", b)
			}
		}

	default:
		fmt.Fprintf(w, "{%q:%q}", "error", "Bad Request")
	}

}

func HandleAppAuthClientCredentials(w http.ResponseWriter, r *http.Request) {
	r.ParseForm()

	w.Write([]byte("<html><body>"))
	w.Write([]byte("APP AUTH - CLIENT CREDENTIALS<br/>"))

	jr := make(map[string]interface{})

	// build access code url
	aurl := fmt.Sprintf("http://%s/token?grant_type=client_credentials", r.Host)

	// download token
	c := appengine.NewContext(r)
	err := downloadAccessToken(c, aurl, &osin.BasicAuth{Username: "1234", Password: "aabbccdd"}, jr)
	if err != nil {
		w.Write([]byte(err.Error()))
		w.Write([]byte("<br/>"))
	}

	// show json error
	if erd, ok := jr["error"]; ok {
		w.Write([]byte(fmt.Sprintf("ERROR: %s<br/>\n", erd)))
	}

	// show json access token
	if at, ok := jr["access_token"]; ok {
		w.Write([]byte(fmt.Sprintf("ACCESS TOKEN: %s<br/>\n", at)))
	}

	w.Write([]byte(fmt.Sprintf("FULL RESULT: %+v<br/>\n", jr)))

	if rt, ok := jr["refresh_token"]; ok {
		rurl := fmt.Sprintf("/appauth/refresh?code=%s", rt)
		w.Write([]byte(fmt.Sprintf("<a href=\"%s\">Refresh Token</a><br/>", rurl)))
	}

	if at, ok := jr["access_token"]; ok {
		rurl := fmt.Sprintf("/appauth/info?code=%s", at)
		w.Write([]byte(fmt.Sprintf("<a href=\"%s\">Info</a><br/>", rurl)))
	}

	w.Write([]byte("</body></html>"))
}

//HandleAppAuthRefresh handles refresh
//USAGE: http://localhost:8080/appauth/refresh?grant_type=refresh_token&code=EdO7wVOtQCWIe117DiIPgg
func (s *AEServer) HandleAppAuthRefresh(w http.ResponseWriter, r *http.Request) {
	r.ParseForm()
	code := r.Form.Get("code")

	if code != "" {
		jr := make(map[string]interface{})

		// build access code url
		aurl := fmt.Sprintf("/token?grant_type=refresh_token&refresh_token=%s", url.QueryEscape(code))

		c := appengine.NewContext(r)
		log.Infof(c, "Getting Refresh")
		err := downloadAccessToken(c, fmt.Sprintf("http://localhost:8081%s", aurl),
			&osin.BasicAuth{Username: "47bef51d-1b4a-4028-b4a1-07dfe3116a9b", Password: "aabbccdd"}, jr)
		if err != nil {
			fmt.Fprintf(w, "{%q:%q}", "error", "Bad Request")
		}
		// show json error
		if _, ok := jr["error"]; ok {
			b, err := json.Marshal(jr)
			if err == nil {
				fmt.Fprintf(w, "%s", b)
			}
		}

		// show json access token
		if _, ok := jr["access_token"]; ok {
			b, err := json.Marshal(jr)
			if err == nil {
				fmt.Fprintf(w, "%s", b)
			}
		}

	} else {
		fmt.Fprintf(w, "{%q:%q}", "error", "Bad Request")
	}
}

func (s *AEServer) HandleAppAuthInfo(w http.ResponseWriter, r *http.Request) {
	r.ParseForm()

	w.Write([]byte("<html><body>"))
	w.Write([]byte("APP AUTH - INFO<br/>"))
	defer w.Write([]byte("</body></html>"))

	code := r.Form.Get("code")

	if code == "" {
		w.Write([]byte("Nothing to do"))
		return
	}

	jr := make(map[string]interface{})

	// build access code url
	aurl := fmt.Sprintf("http://%s/info?code=%s", r.Host, url.QueryEscape(code))

	// download token
	c := appengine.NewContext(r)
	//err := downloadAccessToken(c, aurl, &osin.BasicAuth{Username: "1234", Password: "aabbccdd"}, jr)
	err := downloadAccessToken(c, aurl, nil, jr)
	if err != nil {
		w.Write([]byte(err.Error()))
		w.Write([]byte("<br/>"))
	}

	// show json error
	if erd, ok := jr["error"]; ok {
		w.Write([]byte(fmt.Sprintf("ERROR: %s<br/>\n", erd)))
	}

	// show json access token
	if at, ok := jr["access_token"]; ok {
		w.Write([]byte(fmt.Sprintf("ACCESS TOKEN: %s<br/>\n", at)))
	}

	w.Write([]byte(fmt.Sprintf("FULL RESULT: %+v<br/>\n", jr)))

	if rt, ok := jr["refresh_token"]; ok {
		rurl := fmt.Sprintf("/appauth/refresh?code=%s", rt)
		w.Write([]byte(fmt.Sprintf("<a href=\"%s\">Refresh Token</a><br/>", rurl)))
	}
}

func downloadAccessToken(c context.Context, url string, auth *osin.BasicAuth, output map[string]interface{}) error {
	if auth == nil || url == "" {
		return errors.New(osin.E_INVALID_REQUEST)
	}

	// download access token
	preq, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return err
	}
	if auth != nil {
		preq.SetBasicAuth(auth.Username, auth.Password)
	}

	log.Infof(c, "HANDLE DOWNLOAD TOKEN")

	pclient := urlfetch.Client(c)
	presp, err := pclient.Do(preq)
	if err != nil {
		return err
	}

	if presp.StatusCode != 200 {
		return errors.New("Invalid status code")
	}

	jdec := json.NewDecoder(presp.Body)
	err = jdec.Decode(&output)
	return err
}
