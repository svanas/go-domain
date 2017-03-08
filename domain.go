// Package godomain parses URLs into naked domains.
// Copyright 2017 Stefan van As. All rights reserved.
package godomain

import (
	"bytes"
	"compress/gzip"
	"io"
	"strings"
)

type Domain struct {
	Host string
}

func unzip(data []byte) ([]byte, error) {
	var err error
	var zip *gzip.Reader
	zip, err = gzip.NewReader(bytes.NewBuffer(data))
	if err != nil {
		return nil, err
	}
	var buf bytes.Buffer
	_, err = io.Copy(&buf, zip)
	if err != nil {
		return nil, err
	}
	err = zip.Close()
	if err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

func isIP(host string) bool {
	for i := range host {
		if strings.Index(".0123456789", string(host[i])) == -1 {
			return false
		}
	}
	return true
}

func getHost(rawURL string) string {
	result := strings.ToLower(rawURL)
	// step #1: remove the scheme
	i := strings.Index(result, "://")
	if i > -1 {
		result = result[i+3:]
	}
	// step #2: remove port, path, and query
	for i := range result {
		if strings.Index(":/?", string(result[i])) > -1 {
			result = result[:i]
			break
		}
	}
	return result
}

// Parse parses rawURL into a Domain structure.
func Parse(rawURL string) *Domain {
	domain := new(Domain)
	domain.Host = getHost(rawURL)
	return domain
}

func (d *Domain) Naked() string {
	result := d.Host
	// option #1: we're done if we're having an IP address
	if isIP(result) {
		return result
	}
	// option #2: Mozilla's public suffix list
	var tld string
	for i := len(result) - 1; i >= 0; i-- {
		if string(result[i]) == "." {
			tld = result[i+1:]
			break
		}
	}
	if tld != "" {
		ps := PublicSuffixInstance()
		sl := ps.List(tld)
		for _, s := range sl {
			if s != "" && strings.HasSuffix(result, s) {
				for i := len(result) - len(s) - 1; i >= 0; i-- {
					if string(result[i]) == "." {
						result = result[i+1:]
						return result
					}
				}
			}
		}
	}
	// option #3: use the country-code TLDs
	cc := CountryCodeTLDsInstance()
	sl := cc.List()
	for _, s := range sl {
		if s != "" && strings.HasSuffix(result, s) {
			for i := len(result) - len(s) - 1; i >= 0; i-- {
				if string(result[i]) == "." {
					result = result[i+1:]
					return result
				}
			}
		}
	}
	// option #4: remove everything before the domain, for example: mijn.ing.nl --> ing.nl
	bTLD := false
	for i := len(result) - 1; i >= 0; i-- {
		if string(result[i]) == "." {
			if !bTLD {
				bTLD = true
			} else {
				result = result[i+1:]
				return result
			}
		}
	}
	return result
}
