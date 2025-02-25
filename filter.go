package main

import (
	"log"
	"strings"

	"github.com/hashicorp/go-set"
)

var methods = set.From([]string{"GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS"})

func filter(args []string) []string {
	var i int

	if methods.Contains(strings.ToUpper(args[i])) {
		*method = strings.ToUpper(args[i])
		i++
	} else if len(args) > 0 && *method == "GET" {
		for _, v := range args[1:] {
			// defaults to either GET (with no request data) or POST (with request data).
			// Params
			strs := strings.Split(v, "=")
			if len(strs) == 2 {
				*method = "POST"
				break
			}
			// files
			strs = strings.Split(v, "@")
			if len(strs) == 2 {
				*method = "POST"
				break
			}
		}
	} else if *method == "GET" && body != "" {
		*method = "POST"
	}
	if len(args) <= i {
		log.Fatal("Miss the URL")
	}
	*URL = args[i]
	i++
	return args[i:]
}
