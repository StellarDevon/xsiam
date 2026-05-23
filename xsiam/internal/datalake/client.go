package datalake

import (
	"net/http"
	"time"
)

type Client struct {
	queryURL string
	hecURL   string
	hecToken string
	http     *http.Client
}

func New(queryURL, hecURL, hecToken string) *Client {
	return &Client{
		queryURL: queryURL,
		hecURL:   hecURL,
		hecToken: hecToken,
		http:     &http.Client{Timeout: 30 * time.Second},
	}
}
