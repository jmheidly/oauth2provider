package oauth2provider

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"

	"github.com/credli/osin"
	"github.com/gorilla/mux"

	"golang.org/x/net/context"
	"google.golang.org/appengine"
	"google.golang.org/appengine/log"
	"google.golang.org/appengine/urlfetch"
)

var (
	server  *osin.Server
	storage *AEStorage
)

func init() {
	sconfig := osin.NewServerConfig()
	sconfig.AllowedAuthorizeTypes = osin.AllowedAuthorizeType{osin.CODE, osin.TOKEN}
	sconfig.AllowedAccessTypes = osin.AllowedAccessType{
		osin.AUTHORIZATION_CODE,
		osin.REFRESH_TOKEN,
		osin.PASSWORD,
		osin.CLIENT_CREDENTIALS}
	sconfig.AllowGetAccessRequest = true
	sconfig.AllowClientSecretInParams = true

	storage = NewAEStorage()
	server = osin.NewServer(sconfig, storage)

	r := mux.NewRouter()
	r.HandleFunc("/init", HandleInitClient)
	r.HandleFunc("/authorize", HandleAuthorize)
	r.HandleFunc("/token", HandleToken)
	r.HandleFunc("/info", HandleInfo)
	r.HandleFunc("/app", HandleApp)
	r.HandleFunc("/appauth/code", HandleAppAuthCode)
	r.HandleFunc("/appauth/token", HandleAppAuthToken)
	r.HandleFunc("/appauth/password", HandleAppAuthPassword)
	r.HandleFunc("/appauth/client_credentials", HandleAppAuthClientCredentials)
	r.HandleFunc("/appauth/refresh", HandleAppAuthRefresh)
	r.HandleFunc("/appauth/info", HandleAppAuthInfo)

	http.Handle("/", r)
}

func HandleInitClient(w http.ResponseWriter, r *http.Request) {
	c := appengine.NewContext(r)
	client := &osin.DefaultClient{
		Id:          "1234",
		Secret:      "aabbccdd",
		RedirectUri: "/appauth",
	}
	storage.SetClient(c, "1234", client)
	w.Write([]byte(`<h1>Client set ok</h1>`))
}

func HandleAuthorize(w http.ResponseWriter, r *http.Request) {
	c := appengine.NewContext(r)
	resp := server.NewResponse()
	defer resp.Close()

	if ar := server.HandleAuthorizeRequest(c, resp, r); ar != nil {
		ar.Authorized = true
		server.FinishAuthorizeRequest(c, resp, r, ar)
	}
	if resp.IsError && resp.InternalError != nil {
		log.Errorf(c, "%v", resp.InternalError)
	}
	if !resp.IsError {
		resp.Output["custom_parameter"] = 4567890567
	}
	osin.OutputJSON(resp, w, r)
}

func HandleToken(w http.ResponseWriter, r *http.Request) {
	c := appengine.NewContext(r)
	resp := server.NewResponse()
	defer resp.Close()

	if ar := server.HandleAccessRequest(c, resp, r); ar != nil {
		switch ar.Type {
		case osin.AUTHORIZATION_CODE:
			ar.Authorized = true
		case osin.REFRESH_TOKEN:
			ar.Authorized = true
		case osin.PASSWORD:
			// do password
			if ar.Username == "test" && ar.Password == "test" {
				ar.Authorized = true
			}
		case osin.CLIENT_CREDENTIALS:
			ar.Authorized = true
		}
		server.FinishAccessRequest(c, resp, r, ar)
	}
	if resp.IsError && resp.InternalError != nil {
		log.Errorf(c, "%v", resp.InternalError)
	}
	if !resp.IsError {
		resp.Output["custom_parameter"] = 236663
	}
	osin.OutputJSON(resp, w, r)
}

func HandleInfo(w http.ResponseWriter, r *http.Request) {
	c := appengine.NewContext(r)
	resp := server.NewResponse()
	defer resp.Close()

	if ir := server.HandleInfoRequest(c, resp, r); ir != nil {
		server.FinishInfoRequest(c, resp, r, ir)
	}
	if resp.IsError && resp.InternalError != nil {
		log.Errorf(c, "Stops here... %v", resp.InternalError)
		//log.Errorf(c, "%v", resp.InternalError)
	}
	if !resp.IsError {
		resp.Output["custom_parameter"] = 233333
	}
	osin.OutputJSON(resp, w, r)
}

func HandleApp(w http.ResponseWriter, r *http.Request) {
	w.Write([]byte("<html><body>"))
	w.Write([]byte(fmt.Sprintf("<a href=\"%s\">Init a default client with id 1234 (do this first!)</a><br/>", "/init")))
	w.Write([]byte(fmt.Sprintf("<a href=\"/authorize?response_type=code&client_id=1234&state=xyz&scope=everything&redirect_uri=%s\">Code</a><br/>", url.QueryEscape("/appauth/code"))))
	w.Write([]byte(fmt.Sprintf("<a href=\"/authorize?response_type=token&client_id=1234&state=xyz&scope=everything&redirect_uri=%s\">Implict</a><br/>", url.QueryEscape("/appauth/token"))))
	w.Write([]byte(fmt.Sprintf("<a href=\"/appauth/password\">Password</a><br/>")))
	w.Write([]byte(fmt.Sprintf("<a href=\"/appauth/client_credentials\">Client Credentials</a><br/>")))
	w.Write([]byte("</body></html>"))
}

func HandleAppAuthCode(w http.ResponseWriter, r *http.Request) {
	r.ParseForm()

	code := r.Form.Get("code")

	w.Write([]byte("<html><body>"))
	w.Write([]byte("APP AUTH - CODE<br/>"))
	defer w.Write([]byte("</body></html>"))

	if code == "" {
		w.Write([]byte("Nothing to do"))
		return
	}

	jr := make(map[string]interface{})

	// build access code url
	aurl := fmt.Sprintf("http://%s/token?grant_type=authorization_code&client_id=1234&client_secret=aabbccdd&state=xyz&redirect_uri=%s&code=%s",
		r.Host, url.QueryEscape("/appauth/code"), url.QueryEscape(code))

	// if parse, download and parse json
	if r.Form.Get("doparse") == "1" {
		c := appengine.NewContext(r)
		err := downloadAccessToken(c, aurl, &osin.BasicAuth{"1234", "aabbccdd"}, jr)
		if err != nil {
			w.Write([]byte(err.Error()))
			w.Write([]byte("<br/>"))
		}
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

	// output links
	w.Write([]byte(fmt.Sprintf("<a href=\"%s\">Goto Token URL</a><br/>", aurl)))

	cururl := *r.URL
	curq := cururl.Query()
	curq.Add("doparse", "1")
	cururl.RawQuery = curq.Encode()
	w.Write([]byte(fmt.Sprintf("<a href=\"%s\">Download Token</a><br/>", cururl.String())))

	if rt, ok := jr["refresh_token"]; ok {
		rurl := fmt.Sprintf("/appauth/refresh?code=%s", rt)
		w.Write([]byte(fmt.Sprintf("<a href=\"%s\">Refresh Token</a><br/>", rurl)))
	}

	if at, ok := jr["access_token"]; ok {
		rurl := fmt.Sprintf("/appauth/info?code=%s", at)
		w.Write([]byte(fmt.Sprintf("<a href=\"%s\">Info</a><br/>", rurl)))
	}
}

func HandleAppAuthToken(w http.ResponseWriter, r *http.Request) {
	r.ParseForm()

	w.Write([]byte("<html><body>"))
	w.Write([]byte("APP AUTH - TOKEN<br/>"))

	w.Write([]byte("Response data in fragment - not acessible via server - Nothing to do"))

	w.Write([]byte("</body></html>"))
}

func HandleAppAuthPassword(w http.ResponseWriter, r *http.Request) {
	r.ParseForm()

	w.Write([]byte("<html><body>"))
	w.Write([]byte("APP AUTH - PASSWORD<br/>"))

	jr := make(map[string]interface{})

	// build access code url
	aurl := fmt.Sprintf("http://%s/token?grant_type=password&scope=everything&username=%s&password=%s",
		r.Host, "test", "test")

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

func HandleAppAuthRefresh(w http.ResponseWriter, r *http.Request) {
	r.ParseForm()

	w.Write([]byte("<html><body>"))
	w.Write([]byte("APP AUTH - REFRESH<br/>"))
	defer w.Write([]byte("</body></html>"))

	code := r.Form.Get("code")

	if code == "" {
		w.Write([]byte("Nothing to do"))
		return
	}

	jr := make(map[string]interface{})

	// build access code url
	aurl := fmt.Sprintf("http://%s/token?grant_type=refresh_token&refresh_token=%s", r.Host, url.QueryEscape(code))

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
}

func HandleAppAuthInfo(w http.ResponseWriter, r *http.Request) {
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
	// download access token
	preq, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return err
	}
	if auth != nil {
		preq.SetBasicAuth(auth.Username, auth.Password)
	}

	//pclient := &http.Client{} //Not supported in app engine
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
