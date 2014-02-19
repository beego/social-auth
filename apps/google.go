// Copyright 2014 beego authors
//
// Licensed under the Apache License, Version 2.0 (the "License"): you may
// not use this file except in compliance with the License. You may obtain
// a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
// WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
// License for the specific language governing permissions and limitations
// under the License.
//
// Maintain by https://github.com/slene

package apps

import (
	"fmt"

	"github.com/astaxie/beego/httplib"

	"github.com/beego/social-oauth"
)

type Google struct {
	BaseProvider
}

func (p *Google) GetType() social.SocialType {
	return social.SocialGoogle
}

func (p *Google) GetName() string {
	return "Google"
}

func (p *Google) GetPath() string {
	return "google"
}

func (p *Google) GetUserInfo(tok *social.Token) (map[string]interface{}, error) {
	vals := make(map[string]interface{})

	uri := "https://www.googleapis.com/userinfo/v2/me"
	req := httplib.Get(uri)
	req.Header("Authorization", "Bearer "+tok.AccessToken)
	if err := req.ToJson(&vals); err != nil {
		return vals, err
	}
	if vals["error"] != nil {
		return vals, fmt.Errorf("%v", vals["error"])
	}

	return vals, nil
}

func (p *Google) VerifyAccessToken(tok *social.Token) bool {
	uri := "https://api.github.com/applications/" + p.ClientId + "/tokens/" + tok.AccessToken
	req := httplib.Get(uri)
	req.Header("Authorization", p.getBasicAuth())
	if resp, err := req.Response(); err != nil || resp.StatusCode == 404 {
		return false
	}
	return true
}

var _ social.Provider = new(Google)

func NewGoogle(clientId, secret string) *Google {
	p := new(Google)
	p.App = p
	p.ClientId = clientId
	p.ClientSecret = secret
	p.Scope = "email profile https://www.googleapis.com/auth/plus.login"
	p.AuthURL = "https://accounts.google.com/o/oauth2/auth"
	p.TokenURL = "https://accounts.google.com/o/oauth2/token"
	p.RedirectURL = social.DefaultAppUrl + "login/google/access"
	p.AccessType = "offline"
	p.ApprovalPrompt = "auto"
	return p
}
