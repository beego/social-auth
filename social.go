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

package social

import (
	"encoding/base64"
	"fmt"
	"net/url"
	"strconv"

	"github.com/astaxie/beego"
	"github.com/astaxie/beego/context"
	"github.com/astaxie/beego/utils"
)

const (
	defaultURLPrefix          = "/login/"
	defaultConnectSuccessURL  = "/login?flag=connect_success"
	defaultConnectFailedURL   = "/login?flag=connect_failed"
	defaultLoginURL           = "/login"
	defaultConnectRegisterURL = "/register/connect"
)

type SocialAuth struct {
	app                SocialAuther
	URLPrefix          string
	ConnectSuccessURL  string
	ConnectFailedURL   string
	LoginURL           string
	ConnectRegisterURL string
}

// generate session key for social-auth
func (this *SocialAuth) getSessKey(social SocialType, key string) string {
	return "social_" + fmt.Sprintf("%v", social) + "_" + key
}

// create oauth2 state string
func (this *SocialAuth) createState(ctx *context.Context, social SocialType) string {
	values := make(url.Values, 2)

	if uid, ok := this.app.IsUserLogin(ctx); ok {
		// add uid if user current is login
		values.Add("uid", strconv.FormatInt(int64(uid), 10))
	}

	// our secret string
	values.Add("secret", string(utils.RandomCreateBytes(20)))

	// create state string
	state := base64.URLEncoding.EncodeToString([]byte(values.Encode()))

	// save to session
	name := this.getSessKey(social, "state")
	ctx.Input.CruSession.Set(name, state)

	return state
}

// verify oauth2 state string
func (this *SocialAuth) verifyState(ctx *context.Context, social SocialType) (string, bool) {
	code := ctx.Input.Query("code")
	state := ctx.Input.Query("state")

	if len(code) == 0 || len(state) == 0 {
		return "", false
	}

	name := this.getSessKey(social, "state")

	vu, ok := ctx.Input.CruSession.Get(name).(string)
	if !ok || ok && state != vu {
		return "", false
	}

	return code, true
}

// Get provider according request path. ex: /login/: match /login/github
func (this *SocialAuth) getProvider(ctx *context.Context) Provider {
	path := ctx.Input.Param(":splat")

	p, ok := GetProviderByPath(path)
	if ok {
		return p
	}

	return nil
}

// After OAuthAccess check saved token for ready connect
func (this *SocialAuth) ReadyConnect(ctx *context.Context) (SocialType, bool) {
	var social SocialType

	if s, _ := ctx.Input.CruSession.Get("social_connect").(int); s == 0 {
		return 0, false
	} else {
		social = SocialType(s)
	}

	if !social.Available() {
		return 0, false
	}

	return social, true
}

// Redirect to other social platform
func (this *SocialAuth) OAuthRedirect(ctx *context.Context) (redirect string, failedErr error) {
	_, isLogin := this.app.IsUserLogin(ctx)

	defer func() {
		if len(redirect) == 0 && failedErr != nil {
			if isLogin {
				redirect = this.ConnectFailedURL
			} else {
				redirect = this.LoginURL
			}
		}
	}()

	var p Provider
	if p = this.getProvider(ctx); p == nil {
		failedErr = fmt.Errorf("unknown provider")
		return
	}

	social := p.GetType()
	config := p.GetConfig()
	// create redirect url
	redirect = config.AuthCodeURL(this.createState(ctx, social))
	return
}

// Callback from social platform
func (this *SocialAuth) OAuthAccess(ctx *context.Context) (redirect string, userSocial *UserSocial, failedErr error) {
	_, isLogin := this.app.IsUserLogin(ctx)

	defer func() {
		if len(redirect) == 0 {
			if failedErr != nil {
				if isLogin {
					redirect = this.ConnectFailedURL
				} else {
					redirect = this.LoginURL
				}
			}
		}
	}()

	// check if param has a error key
	if err := ctx.Input.Query("error"); len(err) > 0 {
		failedErr = fmt.Errorf(err)
		return
	}

	// get provider from matched url path
	var p Provider
	if p = this.getProvider(ctx); p == nil {
		failedErr = fmt.Errorf("unknown provider")
		return
	}

	social := p.GetType()

	var code string

	// verify state string
	if c, ok := this.verifyState(ctx, social); !ok {
		failedErr = fmt.Errorf("state not verified")
		return
	} else {
		code = c
	}

	config := p.GetConfig()
	trans := &Transport{config, nil, DefaultTransport}

	// Send code to platform then get token
	if tok, err := trans.Exchange(code); err != nil {
		// get access token
		failedErr = err
	} else if err := tok.GetExtra("error"); err != "" {
		// token has error
		failedErr = fmt.Errorf(err)
	} else if tok.IsEmpty() {
		failedErr = fmt.Errorf("empty access token")
	} else {

		// check
		var uSocial = UserSocial{}
		if ok, err := p.CanConnect(tok, &uSocial); ok {
			// save token to session, for connect
			tk := SocialTokenField{tok}
			ctx.Input.CruSession.Set(this.getSessKey(social, "token"), tk.RawValue())
			ctx.Input.CruSession.Set("social_connect", int(social))

			redirect = this.ConnectRegisterURL

		} else if err == nil {
			if !isLogin {
				// login user
				redirect, failedErr = this.app.LoginUser(ctx, uSocial.Uid)
				if len(redirect) == 0 && failedErr == nil {
					redirect = this.ConnectSuccessURL
				}
			} else {
				redirect = this.ConnectSuccessURL
			}

			// save new access token if it changed
			uSocial.PutToken(tok)

			userSocial = &uSocial

		} else {
			failedErr = err
		}
	}

	return
}

// general use of redirect
func (this *SocialAuth) handleRedirect(ctx *context.Context) {
	redirect, err := this.OAuthRedirect(ctx)
	if err != nil {
		beego.Error("SocialAuth.handleRedirect", err)
	}

	if len(redirect) > 0 {
		ctx.Redirect(302, redirect)
	}
}

// general use of redirect callback
func (this *SocialAuth) handleAccess(ctx *context.Context) {
	redirect, _, err := this.OAuthAccess(ctx)
	if err != nil {
		beego.Error("SocialAuth.handleAccess", err)
	}

	if len(redirect) > 0 {
		ctx.Redirect(302, redirect)
	}
}

// save user social info and login the user
func (this *SocialAuth) ConnectAndLogin(ctx *context.Context, socialType SocialType, uid int) (string, *UserSocial, error) {
	tokKey := this.getSessKey(socialType, "token")

	defer func() {
		// delete connect tok in session
		if ctx.Input.CruSession.Get("social_connect") != nil {
			ctx.Input.CruSession.Delete("social_connect")
		}
		if ctx.Input.CruSession.Get(tokKey) != nil {
			ctx.Input.CruSession.Delete(tokKey)
		}
	}()

	tk := SocialTokenField{}
	value := ctx.Input.CruSession.Get(tokKey)
	if err := tk.SetRaw(value); err != nil {
		return "", nil, err
	}

	var p Provider
	if p, _ = GetProviderByType(socialType); p == nil {
		return "", nil, fmt.Errorf("unknown provider")
	}

	identify, err := p.GetIndentify(tk.Token)
	if err != nil {
		return "", nil, err
	}
	if len(identify) == 0 {
		return "", nil, fmt.Errorf("empty identify")
	}

	userSocial := UserSocial{
		Uid:      uid,
		Type:     socialType,
		Data:     tk,
		Identify: identify,
	}

	if err := userSocial.Save(); err != nil {
		return "", nil, err
	}

	// login user
	loginRedirect, err := this.app.LoginUser(ctx, uid)
	return loginRedirect, &userSocial, nil
}

// create a global SocialAuth instance
func NewSocial(urlPrefix string, socialAuther SocialAuther) *SocialAuth {
	social := new(SocialAuth)
	social.app = socialAuther

	if len(urlPrefix) == 0 {
		urlPrefix = defaultURLPrefix
	}

	if urlPrefix[len(urlPrefix)-1] != '/' {
		urlPrefix += "/"
	}

	social.URLPrefix = urlPrefix

	social.ConnectSuccessURL = defaultConnectSuccessURL
	social.ConnectFailedURL = defaultConnectFailedURL
	social.LoginURL = defaultLoginURL
	social.ConnectRegisterURL = defaultConnectRegisterURL

	return social
}

// create a instance and create filter
func NewWithFilter(urlPrefix string, socialAuther SocialAuther) *SocialAuth {
	social := NewSocial(urlPrefix, socialAuther)

	beego.InsertFilter(social.URLPrefix+"*/access", beego.BeforeRouter, social.handleAccess)
	beego.InsertFilter(social.URLPrefix+"*", beego.BeforeRouter, social.handleRedirect)

	return social
}
