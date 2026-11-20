// Copyright (c) 2026 OpenBao a Series of LF Projects, LLC
// SPDX-License-Identifier: MPL-2.0

// package okta is a minimal wrapper around Okta's push factor API to implement
// MFA validation. Okta provides an official Go API client, but it causes
// considerable binary and dependency bloat.
package okta

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strconv"
	"time"

	"github.com/hashicorp/go-retryablehttp"
)

type Client struct {
	token string
	url   *url.URL
	http  *retryablehttp.Client
}

func New(base, org, token string) (*Client, error) {
	if base == "" {
		base = "okta.com"
	}

	url, err := url.Parse(fmt.Sprintf("https://%s.%s", org, base))
	if err != nil {
		return nil, err
	}

	// This mirrors Okta's own SDK, i.e., don't follow redirects, reattempt 429s
	// up to two times.
	client := retryablehttp.NewClient()
	client.Logger = nil
	client.RetryMax = 2
	client.ErrorHandler = retryablehttp.PassthroughErrorHandler
	client.HTTPClient.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }

	client.CheckRetry = func(ctx context.Context, resp *http.Response, err error) (bool, error) {
		return err == nil && resp.StatusCode == http.StatusTooManyRequests, nil
	}

	client.Backoff = func(min, max time.Duration, attempt int, resp *http.Response) time.Duration {
		if reset, err := strconv.ParseInt(resp.Header.Get("X-Rate-Limit-Reset"), 10, 64); err == nil {
			now, err := http.ParseTime(resp.Header.Get("Date"))
			if err != nil {
				now = time.Now()
			}
			// Add some leeway to account for clock skew.
			if wait := time.Unix(reset, 0).Add(time.Second).Sub(now); wait > 0 {
				return wait
			}
		}
		return retryablehttp.DefaultBackoff(min, max, attempt, resp)
	}

	return &Client{
		token: token,
		url:   url,
		http:  client,
	}, nil
}

func (c *Client) do(ctx context.Context, method, path string, out any) error {
	u, err := url.Parse(path)
	if err != nil {
		return err
	}
	u = c.url.ResolveReference(u)
	if u.Scheme != c.url.Scheme || u.Host != c.url.Host {
		return errors.New("path is outside the configured organization")
	}

	req, err := retryablehttp.NewRequestWithContext(ctx, method, u.String(), nil)
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "SSWS "+c.token)
	req.Header.Set("Accept", "application/json")

	resp, err := c.http.Do(req)
	if err != nil {
		return err
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		// Try pulling out a descriptive error message.
		var detail struct {
			Summary string `json:"errorSummary"`
		}
		_ = json.NewDecoder(resp.Body).Decode(&detail)

		// Otherwise, just name the status code.
		summary := detail.Summary
		if summary == "" {
			summary = fmt.Sprintf("unexpected status code %d", resp.StatusCode)
		}

		return fmt.Errorf("received error from Okta API: %s", summary)
	}

	return json.NewDecoder(resp.Body).Decode(out)
}

type User struct {
	ID string `json:"id"`
}

func (c *Client) ListUsers(ctx context.Context, filter string) ([]User, error) {
	var users []User
	err := c.do(ctx, http.MethodGet, "/api/v1/users?"+url.Values{"filter": {filter}}.Encode(), &users)
	return users, err
}

type Factor struct {
	ID         string `json:"id"`
	FactorType string `json:"factorType"`
}

func (c *Client) ListFactors(ctx context.Context, userID string) ([]Factor, error) {
	var factors []Factor
	err := c.do(ctx, http.MethodGet, "/api/v1/users/"+url.PathEscape(userID)+"/factors", &factors)
	return factors, err
}

type Verification struct {
	FactorResult string `json:"factorResult"`
	Links        struct {
		Poll struct {
			Href string `json:"href"`
		} `json:"poll"`
	} `json:"_links"`
}

func (c *Client) VerifyFactor(ctx context.Context, userID, factorID string) (*Verification, error) {
	var result Verification
	err := c.do(ctx, http.MethodPost, "/api/v1/users/"+url.PathEscape(userID)+"/factors/"+url.PathEscape(factorID)+"/verify", &result)
	return &result, err
}

func (c *Client) Poll(ctx context.Context, href string) (*Verification, error) {
	if href == "" {
		return nil, errors.New("poll href is empty")
	}
	var result Verification
	err := c.do(ctx, http.MethodGet, href, &result)
	return &result, err
}
