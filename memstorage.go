package oauth2provider

// package memcache_storage
//
// import (
// 	"errors"
//
// 	"golang.org/x/net/context"
//
// 	"google.golang.org/appengine/datastore"
// 	"google.golang.org/appengine/log"
//
// 	"github.com/credli/osin"
// )
//
// var (
// 	ClientKind     = "Client"
// 	AccessDataKind = "AccessData"
// 	AuthorizeKind  = "Authorize"
// )
//
// type MemStorage struct {
// }
//
// func NewMemStorage() *MemStorage {
// 	return &MemStorage{}
// }
//
// func (s *MemStorage) Clone() osin.Storage {
// 	return s
// }
//
// func (s *MemStorage) Close() {
// }
//
// // func (s *MemStorage) insertClient(c context.Context, clientId string, secret string, redirectURI string) error {
// // 	//var data map[string]osin.Client
// // 	client := &ClientModel{
// // 		Id:          clientId,
// // 		Secret:      secret,
// // 		RedirectUri: redirectURI,
// // 	}
// //
// // 	if cl, err := s.storage.GetClient(c, client.GetId()); err != nil {
// // 		cm := FromClient(client)
// // 		key := datastore.NewKey(c, ClientKind, cm.GetId(), 0, nil)
// // 		_, err := datastore.Put(c, key, cm)
// // 		if err != nil {
// // 			log.Errorf(c, "Error: %v", err)
// // 			return err
// // 		}
// // 	} else {
// // 		return s.SetClient(c, cl)
// // 	}
// //
// // 	return nil
// // }
//
// func (s *MemStorage) GetClient(c context.Context, id string) (osin.Client, error) {
// 	key := datastore.NewKey(c, ClientKind, id, 0, nil)
// 	var client ClientModel
// 	err := datastore.Get(c, key, &client)
// 	if err != nil {
//
// 		return nil, errors.New("Client not found")
// 	}
// 	return client.ToClient(), nil
// }
//
// func (s *MemStorage) SetClient(c context.Context, client osin.Client) error {
// 	cm := FromClient(client)
//
// 	cm.Id = client.GetId()
// 	cm.Secret = client.GetSecret()
// 	cm.RedirectUri = client.GetRedirectUri()
//
// 	key := datastore.NewKey(c, ClientKind, cm.GetId(), 0, nil)
// 	datastore.Put(c, key, cm)
//
// 	return nil
// }
//
// func (s *MemStorage) SaveAuthorize(c context.Context, data *osin.AuthorizeData) error {
// 	adm := FromAuthorizeData(data)
// 	key := datastore.NewKey(c, AuthorizeKind, adm.Code, 0, nil)
// 	_, err := datastore.Put(c, key, adm)
// 	return err
// }
//
// func (s *MemStorage) LoadAuthorize(c context.Context, code string) (*osin.AuthorizeData, error) {
// 	key := datastore.NewKey(c, AuthorizeKind, code, 0, nil)
// 	var am AuthorizeModel
// 	err := datastore.Get(c, key, &am)
// 	if err != nil {
// 		return nil, errors.New("Authorize not found")
// 	}
// 	var rauth = am.ToAuthorizeData()
// 	client, err := s.GetClient(c, am.ClientID)
// 	if err != nil {
// 		return nil, errors.New("Client not found")
// 	}
// 	rauth.Client = client
// 	return rauth, nil
// }
//
// func (s *MemStorage) RemoveAuthorize(c context.Context, code string) error {
// 	key := datastore.NewKey(c, AuthorizeKind, code, 0, nil)
// 	return datastore.Delete(c, key)
// }
//
// func (s *MemStorage) SaveAccess(c context.Context, data *osin.AccessData) error {
// 	client, err := s.GetClient(c, data.Client.GetId())
// 	if client == nil || err != nil {
// 		return errors.New("Client not found")
// 	}
//
// 	if data.AuthorizeData != nil {
// 		auth, err := s.LoadAuthorize(c, data.AuthorizeData.Code)
// 		if auth == nil || err != nil {
// 			return errors.New("Authorization not found")
// 		}
// 	}
//
// 	var token = FromAccessData(data)
// 	token.ClientID = client.GetId()
//
// 	key := datastore.NewKey(c, AccessDataKind, token.AccessToken, 0, nil)
// 	_, err = datastore.Put(c, key, token)
// 	return err
// }
//
// func (s *MemStorage) LoadAccess(c context.Context, code string) (*osin.AccessData, error) {
// 	log.Infof(c, "Access code: %s", code)
// 	key := datastore.NewKey(c, AccessDataKind, code, 0, nil)
// 	var token AccessDataModel
// 	err := datastore.Get(c, key, &token)
// 	if err != nil {
// 		return nil, errors.New("Access not found")
// 	}
//
// 	var rtoken = token.ToAccessData()
// 	client, err := s.GetClient(c, token.ClientID)
// 	if client == nil || err != nil {
// 		return nil, errors.New("Client not found")
// 	}
// 	rtoken.Client = client
//
// 	if token.AuthorizationCode != "" {
// 		auth, err := s.LoadAuthorize(c, token.AuthorizationCode)
// 		if auth == nil || err != nil {
// 			return nil, errors.New("Authorization not found")
// 		}
// 		rtoken.AuthorizeData = auth
// 	}
//
// 	return rtoken, nil
// }
//
// func (s *MemStorage) RemoveAccess(c context.Context, code string) error {
// 	key := datastore.NewKey(c, AccessDataKind, code, 0, nil)
// 	return datastore.Delete(c, key)
// }
//
// func (s *MemStorage) LoadRefresh(c context.Context, code string) (*osin.AccessData, error) {
// 	q := datastore.NewQuery(AccessDataKind).Filter("refresh_token =", code)
// 	var accesses []*AccessDataModel
// 	keys, err := q.GetAll(c, &accesses)
// 	if err != nil {
// 		return nil, err
// 	}
// 	if len(keys) == 0 {
// 		return nil, errors.New("Refresh not found")
// 	}
// 	return s.LoadAccess(c, keys[0].StringID())
// }
//
// func (s *MemStorage) RemoveRefresh(c context.Context, code string) error {
// 	q := datastore.NewQuery(AccessDataKind).Filter("refresh_token =", code)
// 	var accesses []*AccessDataModel
// 	keys, err := q.GetAll(c, &accesses)
// 	if err != nil {
// 		return err
// 	}
// 	if len(keys) == 0 {
// 		return errors.New("Refresh not found")
// 	}
// 	return s.RemoveAccess(c, keys[0].StringID())
// }
