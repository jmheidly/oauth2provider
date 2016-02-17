package oauth2provider

import (
	"errors"

	"golang.org/x/net/context"

	"google.golang.org/appengine/datastore"
	"google.golang.org/appengine/log"

	"github.com/credli/osin"
)

var (
	ClientKind     = "Client"
	UserKind       = "User"
	AccessDataKind = "AccessData"
	AuthorizeKind  = "Authorize"
)

type AEStorage struct {
}

func NewAEStorage() *AEStorage {
	return &AEStorage{}
}

func (s *AEStorage) Clone() osin.Storage {
	return s
}

func (s *AEStorage) Close() {
}

func (s *AEServer) insertClient(c context.Context, clientId string, secret string, redirectURI string, name string) error {
	//var data map[string]osin.Client
	client := &ClientModel{
		Id:          clientId,
		Secret:      secret,
		RedirectUri: redirectURI,
		Name:        name,
	}

	if cl, err := s.storage.GetClient(c, client.GetId()); err != nil {
		cm := FromClient(client)
		key := datastore.NewKey(c, ClientKind, cm.GetId(), 0, nil)
		_, err := datastore.Put(c, key, cm)
		if err != nil {
			log.Errorf(c, "Error: %v", err)
			return err
		}
	} else {
		return s.SetClient(c, cl)
	}

	return nil
}

func (s *AEServer) GetUser(c context.Context, username string) (*User, error) {
	q := datastore.NewQuery(UserKind).Filter("username =", username)
	var users []*User
	_, err := q.GetAll(c, &users)
	if err != nil {
		return nil, err
		//return nil, errors.New("User not found")
	} else if len(users) > 0 {
		return users[0], nil
	}
	return nil, errors.New("User Not Found")
}

func (s *AEStorage) GetClient(c context.Context, id string) (osin.Client, error) {
	key := datastore.NewKey(c, ClientKind, id, 0, nil)
	var client ClientModel
	err := datastore.Get(c, key, &client)
	if err != nil {

		return nil, errors.New("Client not found")
	}
	return client.ToClient(), nil
}

func (s *AEServer) SetClient(c context.Context, client osin.Client) error {
	cm := FromClient(client)

	cm.Id = client.GetId()
	cm.Secret = client.GetSecret()
	cm.RedirectUri = client.GetRedirectUri()

	key := datastore.NewKey(c, ClientKind, cm.GetId(), 0, nil)
	datastore.Put(c, key, cm)

	return nil
}

func (s *AEStorage) SaveAuthorize(c context.Context, data *osin.AuthorizeData) error {
	adm := FromAuthorizeData(data)
	key := datastore.NewKey(c, AuthorizeKind, adm.Code, 0, nil)
	_, err := datastore.Put(c, key, adm)
	return err
}

func (s *AEStorage) LoadAuthorize(c context.Context, code string) (*osin.AuthorizeData, error) {
	key := datastore.NewKey(c, AuthorizeKind, code, 0, nil)
	var am AuthorizeModel
	err := datastore.Get(c, key, &am)
	if err != nil {
		return nil, errors.New("Authorize not found")
	}
	var rauth = am.ToAuthorizeData()
	client, err := s.GetClient(c, am.ClientID)
	if err != nil {
		return nil, errors.New("Client not found")
	}
	rauth.Client = client
	return rauth, nil
}

func (s *AEStorage) RemoveAuthorize(c context.Context, code string) error {
	key := datastore.NewKey(c, AuthorizeKind, code, 0, nil)
	return datastore.Delete(c, key)
}

func (s *AEStorage) SaveAccess(c context.Context, data *osin.AccessData) error {
	client, err := s.GetClient(c, data.Client.GetId())
	if client == nil || err != nil {
		return errors.New("Client not found")
	}

	if data.AuthorizeData != nil {
		auth, err := s.LoadAuthorize(c, data.AuthorizeData.Code)
		if auth == nil || err != nil {
			return errors.New("Authorization not found")
		}
	}

	var token = FromAccessData(data)
	token.ClientID = client.GetId()

	key := datastore.NewKey(c, AccessDataKind, token.AccessToken, 0, nil)
	_, err = datastore.Put(c, key, token)
	return err
}

func (s *AEStorage) LoadAccess(c context.Context, code string) (*osin.AccessData, error) {
	log.Infof(c, "Access code: %s", code)
	key := datastore.NewKey(c, AccessDataKind, code, 0, nil)
	var token AccessDataModel
	err := datastore.Get(c, key, &token)
	if err != nil {
		return nil, errors.New("Access not found")
	}

	var rtoken = token.ToAccessData()
	client, err := s.GetClient(c, token.ClientID)
	if client == nil || err != nil {
		return nil, errors.New("Client not found")
	}
	rtoken.Client = client

	if token.AuthorizationCode != "" {
		auth, err := s.LoadAuthorize(c, token.AuthorizationCode)
		if auth == nil || err != nil {
			return nil, errors.New("Authorization not found")
		}
		rtoken.AuthorizeData = auth
	}

	return rtoken, nil
}

func (s *AEStorage) RemoveAccess(c context.Context, code string) error {
	key := datastore.NewKey(c, AccessDataKind, code, 0, nil)
	return datastore.Delete(c, key)
}

func (s *AEStorage) LoadRefresh(c context.Context, code string) (*osin.AccessData, error) {
	q := datastore.NewQuery(AccessDataKind).Filter("refresh_token =", code)
	var accesses []*AccessDataModel
	keys, err := q.GetAll(c, &accesses)
	if err != nil {
		return nil, err
	}
	if len(keys) == 0 {
		return nil, errors.New("Refresh not found")
	}
	return s.LoadAccess(c, keys[0].StringID())
}

func (s *AEStorage) RemoveRefresh(c context.Context, code string) error {
	q := datastore.NewQuery(AccessDataKind).Filter("refresh_token =", code)
	var accesses []*AccessDataModel
	keys, err := q.GetAll(c, &accesses)
	if err != nil {
		return err
	}
	if len(keys) == 0 {
		return errors.New("Refresh not found")
	}
	return s.RemoveAccess(c, keys[0].StringID())
}
