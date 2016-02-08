package oauth2provider

import (
	"time"

	"github.com/credli/osin"
)

type ClientModel struct {
	ID          string `datastore:"id"`
	Secret      string `datastore:"secret"`
	RedirectUri string `datastore:"redirect_uri"`
}

func (c *ClientModel) ToClient() osin.Client {
	var client = &osin.DefaultClient{
		Id:          c.ID,
		Secret:      c.Secret,
		RedirectUri: c.RedirectUri,
		UserData:    c,
	}
	return client
}

func FromClient(client osin.Client) *ClientModel {
	return &ClientModel{
		ID:          client.GetId(),
		Secret:      client.GetSecret(),
		RedirectUri: client.GetRedirectUri(),
	}
}

type AccessDataModel struct {
	ClientID            string    `datastore:"client_id"`
	AuthorizationCode   string    `datastore:"authorization_code"`
	PreviousAccessToken string    `datastore:"prev_access_token"`
	AccessToken         string    `datastore:"access_token"`
	RefreshToken        string    `datastore:"refresh_token"`
	ExpiresIn           int32     `datastore:"expires_in"`
	Scope               string    `datastore:"scope"`
	RedirectUri         string    `datastore:"redirect_uri"`
	CreatedAt           time.Time `datastore:"created_at"`
}

func (a *AccessDataModel) ToAccessData() *osin.AccessData {
	return &osin.AccessData{
		AccessToken:  a.AccessToken,
		RefreshToken: a.RefreshToken,
		ExpiresIn:    a.ExpiresIn,
		Scope:        a.Scope,
		RedirectUri:  a.RedirectUri,
		CreatedAt:    a.CreatedAt,
		UserData:     a,
	}
}

func FromAccessData(data *osin.AccessData) *AccessDataModel {
	var ad = AccessDataModel{
		AccessToken:  data.AccessToken,
		RefreshToken: data.RefreshToken,
		ExpiresIn:    data.ExpiresIn,
		Scope:        data.Scope,
		RedirectUri:  data.RedirectUri,
		CreatedAt:    data.CreatedAt,
	}
	if data.AuthorizeData == nil {
		// Client Credentials
		ad.AuthorizationCode = ""
	}
	return &ad
}

type AuthorizeModel struct {
	ClientID    string    `datastore:"client_id"`
	Code        string    `datastore:"code"`
	ExpiresIn   int32     `datastore:"expires_in"`
	Scope       string    `datastore:"scope"`
	RedirectUri string    `datastore:"redirect_uri"`
	State       string    `datastore:"state"`
	CreatedAt   time.Time `datastore:"created_at"`
}

func (a *AuthorizeModel) ToAuthorizeData() *osin.AuthorizeData {
	return &osin.AuthorizeData{
		Code:        a.Code,
		ExpiresIn:   a.ExpiresIn,
		Scope:       a.Scope,
		RedirectUri: a.RedirectUri,
		State:       a.State,
		CreatedAt:   a.CreatedAt,
	}
}

func FromAuthorizeData(auth *osin.AuthorizeData) *AuthorizeModel {
	return &AuthorizeModel{
		ClientID:    auth.Client.GetId(),
		Code:        auth.Code,
		ExpiresIn:   auth.ExpiresIn,
		Scope:       auth.Scope,
		RedirectUri: auth.RedirectUri,
		State:       auth.State,
		CreatedAt:   auth.CreatedAt,
	}
}
