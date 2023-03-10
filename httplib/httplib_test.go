// Copyright 2014 beego Author. All Rights Reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package httplib

import (
	"os"
	"strings"
	"testing"

	"github.com/shoenig/test/must"
)

func TestResponse(t *testing.T) {
	req := Get("http://httpbin.org/get")
	resp, err := req.Response()
	must.NoError(t, err)
	must.NoError(t, resp.Body.Close())
	must.Eq(t, "application/json", resp.Header.Get("Content-Type"))
}

func TestGet(t *testing.T) {
	req := Get("http://httpbin.org/get")
	b, err := req.Bytes()
	must.NoError(t, err)

	str, strErr := req.String()
	must.NoError(t, strErr)
	must.Eq(t, str, string(b))
}

func TestSimplePost(t *testing.T) {
	v := "smallfish"
	req := Post("http://httpbin.org/post")
	req.Param("username", v)

	str, err := req.String()
	must.NoError(t, err)
	must.StrContains(t, str, v)
}

func TestPostFile(t *testing.T) {
	t.Skip("avoid spamming posts")

	v := "smallfish"
	req := Post("http://httpbin.org/post")
	req.Debug(true)
	req.Param("username", v)
	req.PostFile("uploadfile", "httplib_test.go")

	str, err := req.String()
	must.NoError(t, err)
	must.StrContains(t, str, v)
}

func TestSimplePut(t *testing.T) {
	str, err := Put("http://httpbin.org/put").String()
	must.NoError(t, err)
	must.StrContains(t, str, "http://httpbin.org/put")
}

func TestSimpleDelete(t *testing.T) {
	str, err := Delete("http://httpbin.org/delete").String()
	must.NoError(t, err)
	must.StrContains(t, str, "http://httpbin.org/delete")
}

func TestWithCookie(t *testing.T) {
	v := "smallfish"
	_, err1 := Get("http://httpbin.org/cookies/set?k1=" + v).SetEnableCookie(true).String()
	must.NoError(t, err1)

	str, err := Get("http://httpbin.org/cookies").SetEnableCookie(true).String()
	must.NoError(t, err)
	must.StrContains(t, str, v)
}

func TestWithBasicAuth(t *testing.T) {
	str, err := Get("http://httpbin.org/basic-auth/user/passwd").SetBasicAuth("user", "passwd").String()
	must.NoError(t, err)
	must.StrContains(t, str, "authenticated")
}

func TestWithUserAgent(t *testing.T) {
	v := "example"
	str, err := Get("http://httpbin.org/headers").SetUserAgent(v).String()
	must.NoError(t, err)
	must.StrContains(t, str, v)
}

func TestWithSetting(t *testing.T) {
	v := "example"
	var setting BeegoHttpSettings
	setting.EnableCookie = true
	setting.UserAgent = v
	setting.Transport = nil
	SetDefaultSetting(setting)

	str, err := Get("http://httpbin.org/get").String()
	must.NoError(t, err)
	must.StrContains(t, str, v)
}

func TestToJson(t *testing.T) {
	req := Get("http://httpbin.org/ip")
	resp, err := req.Response()
	must.NoError(t, err)
	t.Cleanup(func() {
		_ = resp.Body.Close()
	})

	// httpbin will return http remote addr
	type IP struct {
		Origin string `json:"origin"`
	}
	var ip IP
	must.NoError(t, req.ToJSON(&ip))

	n := strings.Count(ip.Origin, ".")
	must.Eq(t, 3, n)
}

func TestToFile(t *testing.T) {
	f := "example_testfile"
	req := Get("http://httpbin.org/ip")
	must.NoError(t, req.ToFile(f))

	t.Cleanup(func() {
		_ = os.Remove(f)
	})

	b, err := os.ReadFile(f)
	must.NoError(t, err)
	must.StrContains(t, string(b), "origin")
}

func TestHeader(t *testing.T) {
	req := Get("http://httpbin.org/headers")
	req.Header("User-Agent", "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_9_0) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/31.0.1650.57 Safari/537.36")
	str, err := req.String()
	must.NoError(t, err)
	must.StrContains(t, str, "KHTML")
}
