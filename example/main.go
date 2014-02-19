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

package main

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/astaxie/beego"
	"github.com/astaxie/beego/context"
	"github.com/astaxie/beego/orm"

	"github.com/beego/social-auth"
	"github.com/beego/social-auth/apps"
)

func IsUserLogin(ctx *context.Context) (int, bool) {
	if id, ok := ctx.Input.CruSession.Get("login_user").(int); ok && id == 1 {
		return id, true
	}
	return 0, false
}

func Logout(ctx *context.Context) {
	ctx.Input.CruSession.Delete("login_user")
	types := social.GetAllTypes()
	for _, t := range types {
		ctx.Input.CruSession.Delete(t.NameLower())
	}
}

func SetInfoToSession(ctx *context.Context, userSocial *social.UserSocial) {
	ctx.Input.CruSession.Set(userSocial.Type.NameLower(),
		fmt.Sprintf("Identify: %s, AccessToken: %s", userSocial.Identify, userSocial.Data.AccessToken))
}

func HandleRedirect(ctx *context.Context) {
	redirect, err := SocialAuth.OAuthRedirect(ctx)
	if err != nil {
		beego.Error("SocialAuth.handleRedirect", err)
	}

	if len(redirect) > 0 {
		ctx.Redirect(302, redirect)
	}
}

func HandleAccess(ctx *context.Context) {
	redirect, userSocial, err := SocialAuth.OAuthAccess(ctx)
	if err != nil {
		beego.Error("SocialAuth.handleAccess", err)
	}

	if userSocial != nil {
		SetInfoToSession(ctx, userSocial)
	}

	if len(redirect) > 0 {
		ctx.Redirect(302, redirect)
	}
}

type MainRouter struct {
	beego.Controller
}

func (this *MainRouter) Home() {
	this.Redirect("/login", 302)
}

func (this *MainRouter) Login() {
	this.TplNames = "index.tpl"

	_, isLogin := IsUserLogin(this.Ctx)

	switch this.GetString("flag") {
	case "logout":
		Logout(this.Ctx)
		this.Redirect("/login", 302)
		return
	case "connect_success":
		this.Data["Msg"] = "Connect Success"
	case "connect_failed":
		this.Data["Msg"] = "Connect Failed"
	}

	types := social.GetAllTypes()
	this.Data["IsLogin"] = isLogin
	this.Data["Types"] = types

	for _, t := range types {
		this.Data[t.NameLower()] = this.GetSession(t.NameLower())
	}
}

func (this *MainRouter) Connect() {
	this.TplNames = "index.tpl"

	st, ok := SocialAuth.ReadyConnect(this.Ctx)
	if !ok {
		this.Redirect("/login", 302)
		return
	}

	// Your app need custom connect behavior
	// example just direct connect and login
	loginRedirect, userSocial, err := SocialAuth.ConnectAndLogin(this.Ctx, st, 1)
	if err != nil {
		// may be has error
		beego.Error(err)
	} else {
		SetInfoToSession(this.Ctx, userSocial)
	}

	this.Redirect(loginRedirect, 302)
}

type socialAuther struct {
}

func (p *socialAuther) IsUserLogin(ctx *context.Context) (int, bool) {
	return IsUserLogin(ctx)
}

func (p *socialAuther) LoginUser(ctx *context.Context, uid int) (string, error) {
	// fake login the user
	if uid == 1 {
		ctx.Input.CruSession.Set("login_user", 1)
	}
	return "/login", nil
}

var SocialAuth *social.SocialAuth

func init() {
	// setting beego orm
	orm.RegisterDataBase("default", "mysql", "root:root@/social_test?loc=Asia%2FShanghai")
	orm.RunSyncdb("default", false, false)

	// OAuth
	var clientId, secret string
	var err error

	url := beego.AppConfig.String("social_auth_url")
	if len(url) > 0 {
		social.DefaultAppUrl = url
	}

	clientId = beego.AppConfig.String("github_client_id")
	secret = beego.AppConfig.String("github_client_secret")
	err = social.RegisterProvider(apps.NewGithub(clientId, secret))
	if err != nil {
		beego.Error(err)
	}

	clientId = beego.AppConfig.String("google_client_id")
	secret = beego.AppConfig.String("google_client_secret")
	err = social.RegisterProvider(apps.NewGoogle(clientId, secret))
	if err != nil {
		beego.Error(err)
	}

	// global create a SocialAuth and auto set filter
	SocialAuth = social.NewSocial("/login/", new(socialAuther))
	beego.AddFilter("/login/:/access", "AfterStatic", HandleAccess)
	beego.AddFilter("/login/:", "AfterStatic", HandleRedirect)
}

func main() {
	// must enable session engine, default use memory as engine
	beego.SessionOn = true
	beego.SessionProvider = "file"
	beego.SessionSavePath = filepath.Join(os.TempDir(), "social_auth_sess")

	beego.AddFilter("*", "BeforeRouter", func(ctx *context.Context) {
		beego.Info(ctx.Request.Method, ctx.Request.RequestURI)
	})

	mainR := new(MainRouter)
	beego.Router("/", mainR, "get:Home")
	beego.Router("/login", mainR, "get:Login")
	beego.Router("/register/connect", mainR, "get:Connect")
	beego.Run()
}
