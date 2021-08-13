package jwt

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"
)

type jwtToken struct {
	Token     string    `json:"token"`
	ExpiresIn int       `json:"expires_in"`
	IssuedAt  time.Time `json:"issued_at"`
}

type Client struct {
	*http.Client
	token           *jwtToken
	login, password string
	act             actions
}

func (c *Client) SetCredentials(login, password string, act actions) {
	c.login = login
	c.password = password
	c.token = nil
	c.act = act
}

func (c *Client) getNewToken(r *http.Response) error {
	c.token = nil

	b, err := io.ReadAll(r.Body)
	if err != nil && err != io.EOF {
		return err
	}

	if r.Header.Get("www-authenticate") == "" {
		return fmt.Errorf("empty \"www-authenticate\" header. Status: %s. Response: %s", r.Status, string(b))
	}

	realm := WWWAuthHeaderParse(r.Header.Get("www-authenticate"))
	if c.act != "" {
		realm = realm.SetActions(c.act)
	}

	u, err := realm.Url()
	if err != nil {
		return err
	}

	token, err := c.Get(u, c.DefaultHeader())
	if err != nil {
		return err
	}
	defer token.Body.Close()

	c.token = &jwtToken{}
	if err := json.NewDecoder(token.Body).Decode(c.token); err != nil {
		return err
	}

	return nil
}

func (c *Client) DefaultHeader() http.Header {
	hdr := http.Header{}
	hdr.Set("User-Agent", "go-jwt-client/1.0.0")

	if c.token == nil {
		if c.login != "" {
			auth := c.login + ":" + c.password
			hdr.Set("Authorization", "Basic "+base64.StdEncoding.EncodeToString([]byte(auth)))
		}

	} else {
		hdr.Set("Authorization", fmt.Sprintf("Bearer %s", c.token.Token))
	}

	return hdr
}

func (c *Client) Get(url string, header http.Header) (*http.Response, error) {
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return nil, err
	}

	req.Header = c.DefaultHeader()
	if header != nil {
		for k, v := range header {
			req.Header.Set(k, v[0])
		}
	}

	return c.Do(req)
}

func (c *Client) Put(url string, header http.Header, body io.Reader) (*http.Response, error) {
	req, err := http.NewRequest("PUT", url, body)
	if err != nil {
		return nil, err
	}

	req.Header = c.DefaultHeader()
	if header != nil {
		for k, v := range header {
			req.Header.Set(k, v[0])
		}
	}

	return c.Do(req)
}

func (c *Client) ResponseHandle(resp *http.Response) (*http.Response, error) {
	if resp.StatusCode == http.StatusUnauthorized || resp.StatusCode == http.StatusForbidden {
		var err error
		if err = c.getNewToken(resp); err != nil {
			return nil, err
		}

		resp, err = c.Get(resp.Request.URL.String(), nil)
		if err != nil {
			return nil, err
		}

		if resp.StatusCode == http.StatusUnauthorized || resp.StatusCode == http.StatusForbidden {
			return nil, fmt.Errorf("status: %d %s", resp.StatusCode, http.StatusText(resp.StatusCode))
		}
	}

	return resp, nil
}
