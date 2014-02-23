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
	"encoding/json"
	"fmt"
	"strings"

	"github.com/astaxie/beego/orm"
)

const (
	startType SocialType = iota
	SocialGithub
	SocialGoogle
	SocialWeibo
	SocialQQ
	SocialDropbox
	SocialFacebook
	endType
)

var types []SocialType

func GetAllTypes() []SocialType {
	if types == nil {
		types = make([]SocialType, int(endType)-1)
		for i, _ := range types {
			types[i] = SocialType(i + 1)
		}
	}
	return types
}

type SocialType int

func (s SocialType) Available() bool {
	if s > startType && s < endType {
		return true
	}
	return false
}

func (s SocialType) Name() string {
	if p, ok := GetProviderByType(s); ok {
		return p.GetName()
	}
	return ""
}

func (s SocialType) NameLower() string {
	return strings.ToLower(s.Name())
}

type SocialTokenField struct {
	*Token
}

func (e *SocialTokenField) String() string {
	data, _ := json.Marshal(e)
	return string(data)
}

func (e *SocialTokenField) FieldType() int {
	return orm.TypeTextField
}

func (e *SocialTokenField) SetRaw(value interface{}) error {
	switch d := value.(type) {
	case string:
		return json.Unmarshal([]byte(d), e)
	default:
		return fmt.Errorf("<SocialTokenField.SetRaw> unknown value `%v`", value)
	}
	return nil
}

func (e *SocialTokenField) RawValue() interface{} {
	return e.String()
}

type UserSocial struct {
	Id       int
	Uid      int              `orm:"index"`
	Identify string           `orm:"size(200)"`
	Type     SocialType       `orm:"index"`
	Data     SocialTokenField ``
}

func (e *UserSocial) Save() (err error) {
	o := orm.NewOrm()
	if e.Id == 0 {
		_, err = o.Insert(e)
	} else {
		_, err = o.Update(e)
	}
	return
}

func (e *UserSocial) Token() (*Token, error) {
	return e.Data.Token, nil
}

func (e *UserSocial) PutToken(token *Token) error {
	if token == nil {
		return fmt.Errorf("token must be not nil")
	}

	changed := false

	if e.Data.Token == nil {
		e.Data.Token = token
		changed = true
	} else {

		if len(token.AccessToken) > 0 && token.AccessToken != e.Data.AccessToken {
			e.Data.AccessToken = token.AccessToken
			changed = true
		}
		if len(token.RefreshToken) > 0 && token.RefreshToken != e.Data.RefreshToken {
			e.Data.RefreshToken = token.RefreshToken
			changed = true
		}
		if len(token.TokenType) > 0 && token.TokenType != e.Data.TokenType {
			e.Data.TokenType = token.TokenType
			changed = true
		}
		if !token.Expiry.IsZero() && token.Expiry != e.Data.Expiry {
			e.Data.Expiry = token.Expiry
			changed = true
		}
	}

	if changed && e.Id > 0 {
		_, err := orm.NewOrm().Update(e, "Data")
		return err
	}

	return nil
}

func (e *UserSocial) TableUnique() [][]string {
	return [][]string{
		{"Identify", "Type"},
	}
}
func (e *UserSocial) Insert() error {
	if _, err := orm.NewOrm().Insert(e); err != nil {
		return err
	}
	return nil
}

func (e *UserSocial) Read(fields ...string) error {
	if err := orm.NewOrm().Read(e, fields...); err != nil {
		return err
	}
	return nil
}

func (e *UserSocial) Update(fields ...string) error {
	if _, err := orm.NewOrm().Update(e, fields...); err != nil {
		return err
	}
	return nil
}

func (e *UserSocial) Delete() error {
	if _, err := orm.NewOrm().Delete(e); err != nil {
		return err
	}
	return nil
}

func UserSocials() orm.QuerySeter {
	return orm.NewOrm().QueryTable("user_social")
}

// Get UserSocials by uid
func GetSocialsByUid(uid int, socialTypes ...SocialType) ([]*UserSocial, error) {
	var userSocials []*UserSocial
	_, err := UserSocials().Filter("Uid", uid).Filter("Type__in", socialTypes).All(&userSocials)
	if err != nil {
		return nil, err
	}
	return userSocials, nil
}

func init() {
	orm.RegisterModel(new(UserSocial))
}
