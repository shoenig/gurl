# gURL
Go implemented CLI cURL-like tool for humans. `gurl` can be used for testing, debugging, and generally interacting with HTTP servers.

Inspired by [Httpie](https://github.com/jakubroztocil/httpie). Thanks to the author, Jakub.

This is a fork of [astaxie/bat](https://github.com/astaxie/bat). Thanks to the author, `astaxie`.

![](images/logo.png)

![](images/example.png)

- [Main Features](#main-features)
- [Installation](#installation)
- [Usage](#usage)
- [HTTP Method](#http-method)
- [Request URL](#request-url)
- [Request Items](#request-items)
- [JSON](#json)
- [Forms](#forms)
- [HTTP Headers](#http-headers)
- [Authentication](#authentication)
- [Proxies](#proxies)

## Main Features

- Expressive and intuitive syntax
- Built-in JSON support
- Forms and file uploads
- HTTPS, proxies, and authentication
- Arbitrary request data
- Custom headers

## Installation

### Install with Go modules

If you only want to install the `gurl` tool:

	go install github.com/shoenig/gurl@latest

Make sure the `~/go/bin` (or `$GOBIN`) is added into `$PATH`.

## Usage

Hello World:

	$ gurl example.com

Synopsis:

	gurl [flags] [METHOD] URL [ITEM [ITEM]]
	
See also `gurl --help`.	

### Examples

Basic settings - [HTTP method](#http-method), [HTTP headers](#http-headers) and [JSON](#json) data:

	$ gurl PUT example.com X-API-Token:123 name=John

Any custom HTTP method (such as WebDAV, etc.):

	$ gurl -method=PROPFIND example.com name=John

Submitting forms:

	$ gurl -form=true POST example.com hello=World
	
See the request that is being sent using one of the output options:

	$ gurl -print="Hhb" example.com

Use Github API to post a comment on an issue with authentication:

	$ gurl -a USERNAME POST https://api.github.com/repos/shoenig/gurl/issues/1/comments body='gurl is awesome!'

Upload a file using redirected input:

	$ gurl example.com < file.json
	
Download a file and save it via redirected output:

	$ gurl example.com/file > file
	
Download a file wget style:

	$ gurl -download=true example.com/file

Set a custom Host header to work around missing DNS records:

	$ gurl localhost:8000 Host:example.com
	
Following is the detailed documentation. It covers the command syntax, advanced usage, and also features additional examples.
	
## HTTP Method
The name of the HTTP method comes right before the URL argument:

	$ gurl DELETE example.com/todos/7
	
which looks similar to the actual Request-Line that is sent:

DELETE /todos/7 HTTP/1.1

When the METHOD argument is omitted from the command, gurl defaults to either GET (if there is no request data) or POST (with request data).

## Request URL
The only information gurl needs to perform a request is a URL. The default scheme is, somewhat unsurprisingly, http://, and can be omitted from the argument – `gurl example.org` works just fine.

Additionally, curl-like shorthand for localhost is supported. This means that, for example :3000 would expand to http://localhost:3000 If the port is omitted, then port 80 is assumed.

	$ gurl :/foo

	GET /foo HTTP/1.1
	Host: localhost

	$ gurl :3000/bar
	
	GET /bar HTTP/1.1
	Host: localhost:3000

	$ gurl :

	GET / HTTP/1.1
	Host: localhost

If you find yourself manually constructing URLs with query string parameters on the terminal, you may appreciate the `param=value` syntax for appending URL parameters so that you don't have to worry about escaping the & separators. To search for gurl on Google Images you could use this command:

	$ gurl GET www.google.com search=gurl tbm=isch

	GET /?search=gurl&tbm=isch HTTP/1.1

## Request Items
There are a few different request item types that provide a convenient mechanism for specifying HTTP headers, simple JSON and form data, files, and URL parameters.

They are key/value pairs specified after the URL. All have in common that they become part of the actual request that is sent and that their type is distinguished only by the separator used: `:`, `=`, `:=`, `@`, `=@`, and `:=@`. The ones with an `@` expect a file path as value.


|       Item Type         |	          Description           |
| ------------------------| ------------------------------ | 
|HTTP Headers `Name:Value`|Arbitrary HTTP header, e.g. `X-API-Token:123`.|
|Data Fields `field=value`|Request data fields to be serialized as a JSON object (default), or to be form-encoded (--form, -f).|
|Form File Fields `field@/dir/file`|Only available with `-form`, `-f`. For example `screenshot@~/Pictures/img.png`. The presence of a file field results in a `multipart/form-data` request.|
|Form Fields from file `field=@file.txt`|read content from file as value|
|Raw JSON fields `field:=json`, `field:=@file.json`|Useful when sending JSON and one or more fields need to be a Boolean, Number, nested Object, or an Array, e.g., meals:='["ham","spam"]' or pies:=[1,2,3] (note the quotes).|

You can use `\` to escape characters that shouldn't be used as separators (or parts thereof). For instance, foo\==bar will become a data key/value pair (foo= and bar) instead of a URL parameter.

You can also quote values, e.g. `foo="bar baz"`.
## JSON
JSON is the lingua franca of modern web services and it is also the implicit content type gurl by default uses:

If your command includes some data items, they are serialized as a JSON object by default. gurl also automatically sets the following headers, both of which can be overridden:

| header       | value            |
| ------------ | ---------------- |
| Content-Type | application/json |
| Accept       | application/json |

You can use --json=true, -j=true to explicitly set Accept to `application/json` regardless of whether you are sending data (it's a shortcut for setting the header via the usual header notation – `gurl url Accept:application/json`).

Simple example:

	$ gurl PUT example.org name=John email=john@example.com
	PUT / HTTP/1.1
	Accept: application/json
	Accept-Encoding: gzip, deflate
	Content-Type: application/json
	Host: example.org
	
	{
	    "name": "John",
	    "email": "john@example.com"
	}

Even custom/vendored media types that have a json format are getting detected, as long as they implement a json type response and contain a `json` in their declared form:

	$ gurl GET example.com/user/1 Accept:application/vnd.example.v2.0+json
	GET / HTTP/1.1
	Accept: application/vnd.example.v2.0+json
	Accept-Encoding: gzip, deflate
	Content-Type: application/vnd.example.v2.0+json
	Host: example.org

	{
	    "name": "John",
	    "email": "john@example.com"
	}

Non-string fields use the := separator, which allows you to embed raw JSON into the resulting object. Text and raw JSON files can also be embedded into fields using =@ and :=@:

	$ gurl PUT api.example.com/person/1 \
    name=John \
    age:=29 married:=false hobbies:='["http", "pies"]' \  # Raw JSON
    description=@about-john.txt \   # Embed text file
    bookmarks:=@bookmarks.json      # Embed JSON file

	PUT /person/1 HTTP/1.1
	Accept: application/json
	Content-Type: application/json
	Host: api.example.com
	
	{
	    "age": 29,
	    "hobbies": [
	        "http",
	        "pies"
	    ],
	    "description": "John is a nice guy who likes pies.",
	    "married": false,
	    "name": "John",
	    "bookmarks": {
	        "HTTPie": "http://httpie.org",
	    }
	}
	
Send JSON data stored in a file (see redirected input for more examples):

	$ gurl POST api.example.com/person/1 < person.json
	
## Forms
Submitting forms are very similar to sending JSON requests. Often the only difference is in adding the `-form=true`, `-f` option, which ensures that data fields are serialized correctly and Content-Type is set to, `application/x-www-form-urlencoded; charset=utf-8`.

It is possible to make form data the implicit content type instead of JSON via the config file.

### Regular Forms

	$ gurl -f=true POST api.example.org/person/1 name='John Smith' \
    email=john@example.org

	POST /person/1 HTTP/1.1
	Content-Type: application/x-www-form-urlencoded; charset=utf-8

	name=John+Smith&email=john%40example.org

### File Upload Forms

If one or more file fields is present, the serialization and content type is `multipart/form-data`:

	$ gurl -f=true POST example.com/jobs name='John Smith' cv@~/Documents/cv.pdf
	
The request above is the same as if the following HTML form were submitted:

```
<form enctype="multipart/form-data" method="post" action="http://example.com/jobs">
    <input type="text" name="name" />
    <input type="file" name="cv" />
</form>
```

Note that `@` is used to simulate a file upload form field.

## HTTP Headers
To set custom headers you can use the Header:Value notation:

	$ gurl example.org  User-Agent:Bacon/1.0  'Cookie:valued-visitor=yes;foo=bar'  \
    X-Foo:Bar  Referer:http://example.com

	GET / HTTP/1.1
	Accept: */*
	Accept-Encoding: gzip, deflate
	Cookie: valued-visitor=yes;foo=bar
	Host: example.org
	Referer: http://example.com
	User-Agent: Bacon/1.0
	X-Foo: Bar
	
There are a couple of default headers that gurl sets:

	GET / HTTP/1.1
	Accept: */*
	Accept-Encoding: gzip, deflate
	User-Agent: gurl/<version>
	Host: <taken-from-URL>

Any of the default headers can be overridden.

# Authentication
Basic auth:

	$ gurl -a=username:password example.org

# Proxies
You can specify proxies to be used through the --proxy argument for each protocol (which is included in the value in case of redirects across protocols):

	$ gurl --proxy=http://10.10.1.10:3128 example.org
	
With Basic authentication:

	$ gurl --proxy=http://user:pass@10.10.1.10:3128 example.org
	
You can also configure proxies by environment variables HTTP_PROXY and HTTPS_PROXY, and the underlying Requests library will pick them up as well. If you want to disable proxies configured through the environment variables for certain hosts, you can specify them in NO_PROXY.

In your ~/.bash_profile:

	export HTTP_PROXY=http://10.10.1.10:3128
	export HTTPS_PROXY=https://10.10.1.10:1080
	export NO_PROXY=localhost,example.com
