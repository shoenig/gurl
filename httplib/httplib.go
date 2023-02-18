// Copyright 2014 beego Author. All Rights Reserved.
// Copyright 2015 bat authors
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
	"bytes"
	"compress/gzip"
	"crypto/tls"
	"encoding/json"
	"encoding/xml"
	"io"
	"log"
	"mime/multipart"
	"net"
	"net/http"
	"net/http/cookiejar"
	"net/http/httputil"
	"net/url"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/shoenig/ignore"
)

var defaultSetting = BeegoHttpSettings{false, "beegoServer", 60 * time.Second, 60 * time.Second, nil, nil, nil, false, true, true}
var defaultCookieJar http.CookieJar
var settingMutex sync.Mutex

// createDefaultCookie creates a global cookiejar to store cookies.
func createDefaultCookie() {
	settingMutex.Lock()
	defer settingMutex.Unlock()
	defaultCookieJar, _ = cookiejar.New(nil)
}

// SetDefaultSetting is used to overwrite default settings.
func SetDefaultSetting(setting BeegoHttpSettings) {
	settingMutex.Lock()
	defer settingMutex.Unlock()
	defaultSetting = setting
	if defaultSetting.ConnectTimeout == 0 {
		defaultSetting.ConnectTimeout = 60 * time.Second
	}
	if defaultSetting.ReadWriteTimeout == 0 {
		defaultSetting.ReadWriteTimeout = 60 * time.Second
	}
}

// NewBeegoRequest will return *BeegoHttpRequest with the specified method.
func NewBeegoRequest(rawURL, method string) *BeegoHttpRequest {
	var resp http.Response
	u, err := url.Parse(rawURL)
	if err != nil {
		log.Fatal(err)
	}
	req := http.Request{
		URL:        u,
		Method:     method,
		Header:     make(http.Header),
		Proto:      "HTTP/1.1",
		ProtoMajor: 1,
		ProtoMinor: 1,
	}
	return &BeegoHttpRequest{rawURL, &req, map[string]string{}, map[string]string{}, defaultSetting, &resp, nil, nil}
}

// Get returns *BeegoHttpRequest with GET method.
func Get(url string) *BeegoHttpRequest {
	return NewBeegoRequest(url, "GET")
}

// Post returns *BeegoHttpRequest with POST method.
func Post(url string) *BeegoHttpRequest {
	return NewBeegoRequest(url, "POST")
}

// Put returns *BeegoHttpRequest with PUT method.
func Put(url string) *BeegoHttpRequest {
	return NewBeegoRequest(url, "PUT")
}

// Delete returns *BeegoHttpRequest DELETE method.
func Delete(url string) *BeegoHttpRequest {
	return NewBeegoRequest(url, "DELETE")
}

// Head returns *BeegoHttpRequest with HEAD method.
func Head(url string) *BeegoHttpRequest {
	return NewBeegoRequest(url, "HEAD")
}

// BeegoHttpSettings contain client settings.
type BeegoHttpSettings struct {
	ShowDebug        bool
	UserAgent        string
	ConnectTimeout   time.Duration
	ReadWriteTimeout time.Duration
	TlsClientConfig  *tls.Config
	Proxy            func(*http.Request) (*url.URL, error)
	Transport        http.RoundTripper
	EnableCookie     bool
	Gzip             bool
	DumpBody         bool
}

// BeegoHttpRequest provides more useful methods for requesting one url than http.Request.
type BeegoHttpRequest struct {
	url     string
	req     *http.Request
	params  map[string]string
	files   map[string]string
	setting BeegoHttpSettings
	resp    *http.Response
	body    []byte
	dump    []byte
}

// GetRequest returns the http.Request.
func (b *BeegoHttpRequest) GetRequest() *http.Request {
	return b.req
}

// Setting changes the request settings.
func (b *BeegoHttpRequest) Setting(setting BeegoHttpSettings) *BeegoHttpRequest {
	b.setting = setting
	return b
}

// SetBasicAuth sets the request's Authorization header to use HTTP Basic Authentication with the provided username and password.
func (b *BeegoHttpRequest) SetBasicAuth(username, password string) *BeegoHttpRequest {
	b.req.SetBasicAuth(username, password)
	return b
}

// SetEnableCookie sets enable/disable cookiejar
func (b *BeegoHttpRequest) SetEnableCookie(enable bool) *BeegoHttpRequest {
	b.setting.EnableCookie = enable
	return b
}

// SetUserAgent sets User-Agent header field
func (b *BeegoHttpRequest) SetUserAgent(value string) *BeegoHttpRequest {
	b.setting.UserAgent = value
	return b
}

// Debug sets show debug or not when executing request.
func (b *BeegoHttpRequest) Debug(debug bool) *BeegoHttpRequest {
	b.setting.ShowDebug = debug
	return b
}

// DumpBody will dump the body.
func (b *BeegoHttpRequest) DumpBody(dump bool) *BeegoHttpRequest {
	b.setting.DumpBody = dump
	return b
}

// DumpRequest will dump the request.
func (b *BeegoHttpRequest) DumpRequest() []byte {
	return b.dump
}

// SetTimeout sets connect time out and read-write time out for BeegoRequest.
func (b *BeegoHttpRequest) SetTimeout(connectTimeout, readWriteTimeout time.Duration) *BeegoHttpRequest {
	b.setting.ConnectTimeout = connectTimeout
	b.setting.ReadWriteTimeout = readWriteTimeout
	return b
}

// SetTLSClientConfig sets tls connection configurations if visiting https url.
func (b *BeegoHttpRequest) SetTLSClientConfig(config *tls.Config) *BeegoHttpRequest {
	b.setting.TlsClientConfig = config
	return b
}

// Header add header item string in request.
func (b *BeegoHttpRequest) Header(key, value string) *BeegoHttpRequest {
	b.req.Header.Set(key, value)
	return b
}

// SetHost will set the HOST header.
func (b *BeegoHttpRequest) SetHost(host string) *BeegoHttpRequest {
	b.req.Host = host
	return b
}

// SetProtocolVersion the protocol version for incoming requests.
// Client requests always use HTTP/1.1.
func (b *BeegoHttpRequest) SetProtocolVersion(version string) *BeegoHttpRequest {
	if len(version) == 0 {
		version = "HTTP/1.1"
	}

	major, minor, ok := http.ParseHTTPVersion(version)
	if ok {
		b.req.Proto = version
		b.req.ProtoMajor = major
		b.req.ProtoMinor = minor
	}

	return b
}

// SetCookie add cookie into request.
func (b *BeegoHttpRequest) SetCookie(cookie *http.Cookie) *BeegoHttpRequest {
	b.req.Header.Add("Cookie", cookie.String())
	return b
}

// SetTransport sets the beego transport.
func (b *BeegoHttpRequest) SetTransport(transport http.RoundTripper) *BeegoHttpRequest {
	b.setting.Transport = transport
	return b
}

func (b *BeegoHttpRequest) SetProxy(proxy func(*http.Request) (*url.URL, error)) *BeegoHttpRequest {
	b.setting.Proxy = proxy
	return b
}

// Param adds query param in to request.
// params build query string as ?key1=value1&key2=value2...
func (b *BeegoHttpRequest) Param(key, value string) *BeegoHttpRequest {
	b.params[key] = value
	return b
}

func (b *BeegoHttpRequest) PostFile(formname, filename string) *BeegoHttpRequest {
	b.files[formname] = filename
	return b
}

// Body adds request raw body.
// it supports string and []byte.
func (b *BeegoHttpRequest) Body(data interface{}) *BeegoHttpRequest {
	switch t := data.(type) {
	case string:
		bf := bytes.NewBufferString(t)
		b.req.Body = io.NopCloser(bf)
		b.req.ContentLength = int64(len(t))
	case []byte:
		bf := bytes.NewBuffer(t)
		b.req.Body = io.NopCloser(bf)
		b.req.ContentLength = int64(len(t))
	}
	return b
}

// JsonBody adds request raw body encoding by JSON.
func (b *BeegoHttpRequest) JsonBody(obj interface{}) (*BeegoHttpRequest, error) {
	if b.req.Body == nil && obj != nil {
		buf := bytes.NewBuffer(nil)
		enc := json.NewEncoder(buf)
		if err := enc.Encode(obj); err != nil {
			return b, err
		}
		b.req.Body = io.NopCloser(buf)
		b.req.ContentLength = int64(buf.Len())
		b.req.Header.Set("Content-Type", "application/json")
	}
	return b, nil
}

func (b *BeegoHttpRequest) buildUrl(paramBody string) {
	// build GET url with query string
	if b.req.Method == "GET" && len(paramBody) > 0 {
		if strings.Index(b.url, "?") != -1 {
			b.url += "&" + paramBody
		} else {
			b.url = b.url + "?" + paramBody
		}
		return
	}

	// build POST/PUT/PATCH url and body
	if (b.req.Method == "POST" || b.req.Method == "PUT" || b.req.Method == "PATCH") && b.req.Body == nil {
		// with files
		if len(b.files) > 0 {
			pr, pw := io.Pipe()
			bodyWriter := multipart.NewWriter(pw)
			go func() {
				for formName, filename := range b.files {
					fileWriter, err := bodyWriter.CreateFormFile(formName, filename)
					if err != nil {
						log.Fatal(err)
					}
					fh, err := os.Open(filename)
					if err != nil {
						log.Fatal(err)
					}
					_, err = io.Copy(fileWriter, fh)
					ignore.Close(fh)
					if err != nil {
						log.Fatal(err)
					}
				}
				for k, v := range b.params {
					ignore.Error(bodyWriter.WriteField(k, v))
				}
				ignore.Close(bodyWriter)
				ignore.Close(pw)
			}()
			b.Header("Content-Type", bodyWriter.FormDataContentType())
			b.req.Body = io.NopCloser(pr)
			return
		}

		// with params
		if len(paramBody) > 0 {
			b.Header("Content-Type", "application/x-www-form-urlencoded")
			b.Body(paramBody)
		}
	}
}

func (b *BeegoHttpRequest) getResponse() (*http.Response, error) {
	if b.resp.StatusCode != 0 {
		return b.resp, nil
	}
	resp, err := b.SendOut()
	if err != nil {
		return nil, err
	}
	b.resp = resp
	return resp, nil
}

func (b *BeegoHttpRequest) SendOut() (*http.Response, error) {
	var paramBody string
	if len(b.params) > 0 {
		var buf bytes.Buffer
		for k, v := range b.params {
			buf.WriteString(url.QueryEscape(k))
			buf.WriteByte('=')
			buf.WriteString(url.QueryEscape(v))
			buf.WriteByte('&')
		}
		paramBody = buf.String()
		paramBody = paramBody[0 : len(paramBody)-1]
	}

	b.buildUrl(paramBody)
	reqURL, err := url.Parse(b.url)
	if err != nil {
		return nil, err
	}

	b.req.URL = reqURL

	trans := b.setting.Transport

	if trans == nil {
		// create default transport
		trans = &http.Transport{
			TLSClientConfig: b.setting.TlsClientConfig,
			Proxy:           b.setting.Proxy,
			Dial:            TimeoutDialer(b.setting.ConnectTimeout, b.setting.ReadWriteTimeout),
		}
	} else {
		// if b.transport is *http.Transport then set the settings.
		if t, ok := trans.(*http.Transport); ok {
			if t.TLSClientConfig == nil {
				t.TLSClientConfig = b.setting.TlsClientConfig
			}
			if t.Proxy == nil {
				t.Proxy = b.setting.Proxy
			}
			if t.Dial == nil {
				t.Dial = TimeoutDialer(b.setting.ConnectTimeout, b.setting.ReadWriteTimeout)
			}
		}
	}

	var jar http.CookieJar = nil
	if b.setting.EnableCookie {
		if defaultCookieJar == nil {
			createDefaultCookie()
		}
		jar = defaultCookieJar
	}

	client := &http.Client{
		Transport: trans,
		Jar:       jar,
	}

	if b.setting.UserAgent != "" && b.req.Header.Get("User-Agent") == "" {
		b.req.Header.Set("User-Agent", b.setting.UserAgent)
	}

	if b.setting.ShowDebug {
		dump, err := httputil.DumpRequest(b.req, b.setting.DumpBody)
		if err != nil {
			println(err.Error())
		}
		b.dump = dump
	}
	return client.Do(b.req)
}

// String returns the body string in response.
// it calls Response inner.
func (b *BeegoHttpRequest) String() (string, error) {
	data, err := b.Bytes()
	if err != nil {
		return "", err
	}

	return string(data), nil
}

// Bytes returns the body []byte in response.
// it calls Response inner.
func (b *BeegoHttpRequest) Bytes() ([]byte, error) {
	if b.body != nil {
		return b.body, nil
	}
	resp, err := b.getResponse()
	if err != nil {
		return nil, err
	}
	if resp.Body == nil {
		return nil, nil
	}
	defer ignore.Close(resp.Body)

	if b.setting.Gzip && resp.Header.Get("Content-Encoding") == "gzip" {
		reader, err := gzip.NewReader(resp.Body)
		if err != nil {
			return nil, err
		}
		b.body, err = io.ReadAll(reader)
	} else {
		b.body, err = io.ReadAll(resp.Body)
	}
	if err != nil {
		return nil, err
	}
	return b.body, nil
}

// ToFile saves the body data in response to one file.
// it calls Response inner.
func (b *BeegoHttpRequest) ToFile(filename string) error {
	f, err := os.Create(filename)
	if err != nil {
		return err
	}
	defer ignore.Close(f)

	resp, err := b.getResponse()
	if err != nil {
		return err
	}
	if resp.Body == nil {
		return nil
	}
	defer ignore.Close(resp.Body)

	_, err = io.Copy(f, resp.Body)
	return err
}

// ToJSON returns the map that marshals from the body bytes as json in response .
// it calls Response inner.
func (b *BeegoHttpRequest) ToJSON(v interface{}) error {
	data, err := b.Bytes()
	if err != nil {
		return err
	}
	return json.Unmarshal(data, v)
}

// ToXML returns the map that marshals from the body bytes as xml in response .
// it calls Response inner.
func (b *BeegoHttpRequest) ToXML(v interface{}) error {
	data, err := b.Bytes()
	if err != nil {
		return err
	}
	return xml.Unmarshal(data, v)
}

// Response executes request client gets response mannually.
func (b *BeegoHttpRequest) Response() (*http.Response, error) {
	return b.getResponse()
}

// TimeoutDialer returns functions of connection dialer with timeout settings for http.Transport Dial field.
func TimeoutDialer(cTimeout time.Duration, rwTimeout time.Duration) func(net, addr string) (c net.Conn, err error) {
	return func(netw, addr string) (net.Conn, error) {
		conn, err := net.DialTimeout(netw, addr, cTimeout)
		if err != nil {
			return nil, err
		}
		ignore.Error(conn.SetDeadline(time.Now().Add(rwTimeout)))
		return conn, nil
	}
}
