package gelato

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net"
	"net/http"
	"time"
)

var (
	contentTypeJSON   = "application/json"
	dialTimeout       = 60 * time.Second
	httpClientTimeout = 30 * time.Minute
	callTimeout       = 30 * time.Minute

	transport = &http.Transport{
		Dial: (&net.Dialer{
			Timeout: dialTimeout,
		}).Dial,
	}
	httpClient = &http.Client{
		Transport: transport,
		Timeout:   httpClientTimeout,
	}
)

// PostResponse is returned from a Gelato relayer after POSTing a request
type PostResponse struct {
	TaskID string `json"taskId"`
}

func postRPC(endpoint string, data interface{}) (*PostResponse, error) {
	bz, err := json.Marshal(data)
	if err != nil {
		return nil, err
	}

	buf := &bytes.Buffer{}
	_, err = buf.Write(bz)
	if err != nil {
		return nil, err
	}

	r, err := http.NewRequest("POST", endpoint, buf)
	if err != nil {
		return nil, fmt.Errorf("failed to create HTTP request: %w", err)
	}
	r.Header.Set("Content-Type", contentTypeJSON)

	ctx, cancel := context.WithTimeout(context.Background(), callTimeout)
	defer cancel()
	r = r.WithContext(ctx)

	resp, err := httpClient.Do(r)
	if err != nil {
		return nil, fmt.Errorf("failed to post request: %w", err)
	}

	defer func() {
		_ = resp.Body.Close()
	}()

	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read response body: %w", err)
	}

	var pr *PostResponse
	if err = json.Unmarshal(body, &pr); err != nil {
		return nil, err
	}

	return pr, nil
}

// TODO: update this type https://docs.gelato.network/developer-products/gelato-relay-sdk/request-types#querying-task-status
type GetResponse struct {
	Message string `json:"message"`
}

func getRPC(endpoint string) (*GetResponse, error) {
	r, err := http.NewRequest("GET", endpoint, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create HTTP request: %w", err)
	}
	r.Header.Set("Content-Type", contentTypeJSON)

	ctx, cancel := context.WithTimeout(context.Background(), callTimeout)
	defer cancel()
	r = r.WithContext(ctx)

	resp, err := httpClient.Do(r)
	if err != nil {
		return nil, fmt.Errorf("failed to post request: %w", err)
	}

	defer func() {
		_ = resp.Body.Close()
	}()

	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read response body: %w", err)
	}

	var gr *GetResponse
	if err = json.Unmarshal(body, &gr); err != nil {
		return nil, err
	}

	return gr, nil
}
