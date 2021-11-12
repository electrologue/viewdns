// Package viewdns contains a viewdns.info API client.
package viewdns

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"path"
	"strconv"
	"time"
)

const defaultBaseURL = "https://api.viewdns.info"

// Client is a ViewDNS API client.
type Client struct {
	apiKey  string
	baseURL *url.URL

	HTTPClient *http.Client
}

// NewClient creates a new Client.
func NewClient(apiKey string) *Client {
	baseURL, _ := url.Parse(defaultBaseURL)

	return &Client{
		apiKey:     apiKey,
		baseURL:    baseURL,
		HTTPClient: &http.Client{Timeout: 5 * time.Second},
	}
}

// AbuseLookup Used to find the abuse contact address for a domain name.
// This is where you would send complaints about spam originating from that domain.
//
// URL:
//   https://api.viewdns.info/abuselookup/
//
// Parameters
//  - `domain` - the domain name to find the abuse contact for
//  - `output` - the output format required ('xml' or 'json')
//  - `apikey` - your api key
//
// GET https://api.viewdns.info/abuselookup/?domain=twitter.com&apikey=yourapikey&output=output_type
func (c Client) AbuseLookup(ctx context.Context, domain string) (string, error) {
	endpoint, err := c.baseURL.Parse(path.Join(c.baseURL.Path, "abuselookup"))
	if err != nil {
		return "", err
	}

	query := endpoint.Query()
	query.Set("domain", domain)
	query.Set("apikey", c.apiKey)
	query.Set("output", "json")
	endpoint.RawQuery = query.Encode()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint.String(), http.NoBody)
	if err != nil {
		return "", err
	}

	resp, err := c.HTTPClient.Do(req)
	if err != nil {
		return "", err
	}

	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		data, _ := io.ReadAll(resp.Body)
		return "", fmt.Errorf("%d: %s", resp.StatusCode, string(data))
	}

	var apiResp AbuseLookupResponse
	err = json.NewDecoder(resp.Body).Decode(&apiResp)
	if err != nil {
		return "", err
	}

	return apiResp.Response.Abusecontact, nil
}

// ChineseFirewall Checks whether a site is blocked by the Great Firewall of China.
//
// This test checks across a number of servers from various locations in mainland China
// to determine if access to the site provided is possible from behind the Great Firewall of China.
//
// This test checks for symptoms of DNS poisoning, one of the more common methods used by the Chinese government to block access to websites.
//
// URL:
//   https://api.viewdns.info/chinesefirewall/
//
// Parameters:
//  - `domain` - the domain name to test
//  - `output` - the output format required ('xml' or 'json')
//  - `apikey` - your api key
//
// GET https://api.viewdns.info/chinesefirewall/?domain=test.com&apikey=yourapikey&output=output_type
func (c Client) ChineseFirewall(ctx context.Context, domain string) (*ChineseFirewall, error) {
	endpoint, err := c.baseURL.Parse(path.Join(c.baseURL.Path, "chinesefirewall"))
	if err != nil {
		return nil, err
	}

	query := endpoint.Query()
	query.Set("domain", domain)
	query.Set("apikey", c.apiKey)
	query.Set("output", "json")
	endpoint.RawQuery = query.Encode()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint.String(), http.NoBody)
	if err != nil {
		return nil, err
	}

	resp, err := c.HTTPClient.Do(req)
	if err != nil {
		return nil, err
	}

	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		data, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("%d: %s", resp.StatusCode, string(data))
	}

	var apiResp ChineseFirewallResponse
	err = json.NewDecoder(resp.Body).Decode(&apiResp)
	if err != nil {
		return nil, err
	}

	return &apiResp.Response, nil
}

// DNSPropagationChecker Check whether recent changes to DNS entries have propagated to DNS servers all over the world.
//
// Useful in troubleshooting DNS issues that appear to be isolated to one geographic region.
// Provides a status report on DNS propagation globally.
//
// URL:
//   https://api.viewdns.info/propagation/
//
// Parameters:
//  - `domain` - the domain name to test
//  - `output` - the output format required ('xml' or 'json')
//  - `apikey` - your api key
//
// GET https://api.viewdns.info/propagation/?domain=test.com&apikey=yourapikey&output=output_type
func (c Client) DNSPropagationChecker(ctx context.Context, domain string) ([]Server, error) {
	endpoint, err := c.baseURL.Parse(path.Join(c.baseURL.Path, "propagation"))
	if err != nil {
		return nil, err
	}

	query := endpoint.Query()
	query.Set("domain", domain)
	query.Set("apikey", c.apiKey)
	query.Set("output", "json")
	endpoint.RawQuery = query.Encode()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint.String(), http.NoBody)
	if err != nil {
		return nil, err
	}

	resp, err := c.HTTPClient.Do(req)
	if err != nil {
		return nil, err
	}

	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		data, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("%d: %s", resp.StatusCode, string(data))
	}

	var apiResp DNSPropagationCheckerResponse
	err = json.NewDecoder(resp.Body).Decode(&apiResp)
	if err != nil {
		return nil, err
	}

	return apiResp.Response.Servers, nil
}

// DNSRecordLookup View all configured DNS records (A, MX, CNAME etc.) for a specified domain name.
//
// URL:
//   https://api.viewdns.info/dnsrecord/
//
// Parameters:
//   - `domain` - the domain name to lookup DNS records for
//   - `recordtype` - the type of DNS record you wish to retrieve (default 'ANY')
//   - `output` - the output format required ('xml' or 'json')
//   - `apikey` - your api key
//
// GET https://api.viewdns.info/dnsrecord/?domain=twitter.com&recordtype=A&apikey=yourapikey&output=output_type
func (c Client) DNSRecordLookup(ctx context.Context, domain, recordType string) ([]DNSRecord, error) {
	endpoint, err := c.baseURL.Parse(path.Join(c.baseURL.Path, "dnsrecord"))
	if err != nil {
		return nil, err
	}

	query := endpoint.Query()
	query.Set("domain", domain)
	query.Set("recordtype", recordType)
	query.Set("apikey", c.apiKey)
	query.Set("output", "json")
	endpoint.RawQuery = query.Encode()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint.String(), http.NoBody)
	if err != nil {
		return nil, err
	}

	resp, err := c.HTTPClient.Do(req)
	if err != nil {
		return nil, err
	}

	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		data, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("%d: %s", resp.StatusCode, string(data))
	}

	var apiResp DNSRecordLookupResponse
	err = json.NewDecoder(resp.Body).Decode(&apiResp)
	if err != nil {
		return nil, err
	}

	return apiResp.Response.Records, nil
}

// Whois Domain / IP Whois.
//
// Displays owner/contact information for a domain name. Can also be used to determine if a domain name is registered or not.
//
// Note:
// 		This tool is not available to free API key users.
// 		Access is restricted to paid API keys only.
//
// URL:
//   https://api.viewdns.info/whois/
//
// Parameters:
//  - `domain` - the domain or ip to perform a whois lookup on
//  - `output` - the output format required ('xml' or 'json')
//  - `apikey` - your api key
//
// GET https://api.viewdns.info/whois/?domain=twitter.com&apikey=yourapikey&output=output_type
func (c Client) Whois(ctx context.Context, domainOrIP string) (*Whois, error) {
	endpoint, err := c.baseURL.Parse(path.Join(c.baseURL.Path, "whois"))
	if err != nil {
		return nil, err
	}

	query := endpoint.Query()
	query.Set("domain", domainOrIP)
	query.Set("apikey", c.apiKey)
	query.Set("output", "json")
	endpoint.RawQuery = query.Encode()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint.String(), http.NoBody)
	if err != nil {
		return nil, err
	}

	resp, err := c.HTTPClient.Do(req)
	if err != nil {
		return nil, err
	}

	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		data, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("%d: %s", resp.StatusCode, string(data))
	}

	var apiResp WhoisResponse
	err = json.NewDecoder(resp.Body).Decode(&apiResp)
	if err != nil {
		return nil, err
	}

	return &apiResp.Response, nil
}

// FreeEmailLookup Find out if a domain name provides free email addresses.
//
// Search is performed on a custom made list of thousands of known free email hosts.
//
// URL:
//   https://api.viewdns.info/freeemail/
//
// Parameters
//  - `domain` - the domain name to test for free email services
//  - `output` - the output format required ('xml' or 'json')
//  - `apikey` - your api key
//
// GET https://api.viewdns.info/freeemail/?domain=test.com&apikey=yourapikey&output=output_type
func (c Client) FreeEmailLookup(ctx context.Context, domain string) (string, error) {
	endpoint, err := c.baseURL.Parse(path.Join(c.baseURL.Path, "freeemail"))
	if err != nil {
		return "", err
	}

	query := endpoint.Query()
	query.Set("domain", domain)
	query.Set("apikey", c.apiKey)
	query.Set("output", "json")
	endpoint.RawQuery = query.Encode()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint.String(), http.NoBody)
	if err != nil {
		return "", err
	}

	resp, err := c.HTTPClient.Do(req)
	if err != nil {
		return "", err
	}

	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		data, _ := io.ReadAll(resp.Body)
		return "", fmt.Errorf("%d: %s", resp.StatusCode, string(data))
	}

	var apiResp FreeEmailLookupResponse
	err = json.NewDecoder(resp.Body).Decode(&apiResp)
	if err != nil {
		return "", err
	}

	return apiResp.Response.Result, nil
}

// GetHTTPHeaders Retrieves the HTTP headers of a remote domain.
//
// Useful in determining the web server (and version) in use and much more.
//
// URL:
//    https://api.viewdns.info/httpheaders/
//
// Parameters;
//
//  - `domain` - the domain to retrieve the HTTP headers for
//  - `output` - the output format required ('xml' or 'json')
//  - `apikey` - your api key
//
// GET https://api.viewdns.info/httpheaders/?domain=twitter.com&apikey=yourapikey&output=output_type
func (c Client) GetHTTPHeaders(ctx context.Context, domain string) ([]Header, error) {
	endpoint, err := c.baseURL.Parse(path.Join(c.baseURL.Path, "httpheaders"))
	if err != nil {
		return nil, err
	}

	query := endpoint.Query()
	query.Set("domain", domain)
	query.Set("apikey", c.apiKey)
	query.Set("output", "json")
	endpoint.RawQuery = query.Encode()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint.String(), http.NoBody)
	if err != nil {
		return nil, err
	}

	resp, err := c.HTTPClient.Do(req)
	if err != nil {
		return nil, err
	}

	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		data, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("%d: %s", resp.StatusCode, string(data))
	}

	var apiResp GetHTTPHeadersResponse
	err = json.NewDecoder(resp.Body).Decode(&apiResp)
	if err != nil {
		return nil, err
	}

	return apiResp.Response.Headers, nil
}

// GooglePagerankChecker Instantly check the Google Pagerank of any domain
// without the need to install the Google toolbar or any other software.
//
// Google Pagerank is a measurement of the importance of your site obtained by looking at the importance of all sites linking to it.
//
// There is debate as to whether focusing on obtaining a higher Google Pagerank is important for Search Engine Optimisation (SEO) or not,
// but generally speaking it is agreed that the higher your sites Google Pagerank, the better.
//
// The possible values for Google Pagerank are 1-10 with 10 being the best Google Pagerank possible.
//
// URL:
//   https://api.viewdns.info/pagerank/
//
// Parameters:
//  - `domain` - the domain to check the pagerank for
//  - `output` - the output format required ('xml' or 'json')
//  - `apikey` - your api key
//
// GET https://api.viewdns.info/pagerank/?domain=twitter.com&apikey=yourapikey&output=output_type
func (c Client) GooglePagerankChecker(ctx context.Context, domain string) (string, error) {
	endpoint, err := c.baseURL.Parse(path.Join(c.baseURL.Path, "pagerank"))
	if err != nil {
		return "", err
	}

	query := endpoint.Query()
	query.Set("domain", domain)
	query.Set("apikey", c.apiKey)
	query.Set("output", "json")
	endpoint.RawQuery = query.Encode()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint.String(), http.NoBody)
	if err != nil {
		return "", err
	}

	resp, err := c.HTTPClient.Do(req)
	if err != nil {
		return "", err
	}

	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		data, _ := io.ReadAll(resp.Body)
		return "", fmt.Errorf("%d: %s", resp.StatusCode, string(data))
	}

	var apiResp GooglePagerankCheckerResponse
	err = json.NewDecoder(resp.Body).Decode(&apiResp)
	if err != nil {
		return "", err
	}

	return apiResp.Response.Pagerank, nil
}

// IPHistory Shows a historical list of IP addresses a given domain name has been hosted
// on as well as where that IP address is geographically located,
// and the owner of that IP address.
//
// URL:
//   https://api.viewdns.info/iphistory/
//
// Parameters:
//  - `domain` - the domain to find historical IP addresses for
//  - `output` - the output format required ('xml' or 'json')
//  - `apikey` - your api key
//
// GET https://api.viewdns.info/iphistory/?domain=example.com&apikey=yourapikey&output=output_type
func (c Client) IPHistory(ctx context.Context, domain string) ([]IPRecord, error) {
	endpoint, err := c.baseURL.Parse(path.Join(c.baseURL.Path, "iphistory"))
	if err != nil {
		return nil, err
	}

	query := endpoint.Query()
	query.Set("domain", domain)
	query.Set("apikey", c.apiKey)
	query.Set("output", "json")
	endpoint.RawQuery = query.Encode()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint.String(), http.NoBody)
	if err != nil {
		return nil, err
	}

	resp, err := c.HTTPClient.Do(req)
	if err != nil {
		return nil, err
	}

	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		data, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("%d: %s", resp.StatusCode, string(data))
	}

	var apiResp IPHistoryResponse
	err = json.NewDecoder(resp.Body).Decode(&apiResp)
	if err != nil {
		return nil, err
	}

	return apiResp.Response.Records, nil
}

// IPLocationFinder This tool will display geographic information about a supplied IP address
// including city, country, latitude, longitude and more.
//
// URL:
//   https://api.viewdns.info/iplocation/
//
// Parameters:
//  - `ip` - the ip address to find the location of
//  - `output` - the output format required ('xml' or 'json')
//  - `apikey` - your api key
//
// GET https://api.viewdns.info/iplocation/?ip=11.11.11.11&apikey=yourapikey&output=output_type
func (c Client) IPLocationFinder(ctx context.Context, ip string) (*IPLocation, error) {
	endpoint, err := c.baseURL.Parse(path.Join(c.baseURL.Path, "iplocation"))
	if err != nil {
		return nil, err
	}

	query := endpoint.Query()
	query.Set("ip", ip)
	query.Set("apikey", c.apiKey)
	query.Set("output", "json")
	endpoint.RawQuery = query.Encode()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint.String(), http.NoBody)
	if err != nil {
		return nil, err
	}

	resp, err := c.HTTPClient.Do(req)
	if err != nil {
		return nil, err
	}

	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		data, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("%d: %s", resp.StatusCode, string(data))
	}

	var apiResp IPLocationFinderResponse
	err = json.NewDecoder(resp.Body).Decode(&apiResp)
	if err != nil {
		return nil, err
	}

	return &apiResp.Response, nil
}

// IranFirewall Test if any website is accessible using the Internet in Iran in real-time.
//
// URL:
//   https://api.viewdns.info/iranfirewall/
//
// Parameters
//  - `siteurl` - the URL to test
//  - `output` - the output format required ('xml' or 'json')
//  - `apikey` - your api key
//
// GET https://api.viewdns.info/iranfirewall/?siteurl=http://www.test.com&apikey=yourapikey&output=output_type
func (c Client) IranFirewall(ctx context.Context, site string) (string, error) {
	endpoint, err := c.baseURL.Parse(path.Join(c.baseURL.Path, "iranfirewall"))
	if err != nil {
		return "", err
	}

	query := endpoint.Query()
	query.Set("siteurl", site)
	query.Set("apikey", c.apiKey)
	query.Set("output", "json")
	endpoint.RawQuery = query.Encode()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint.String(), http.NoBody)
	if err != nil {
		return "", err
	}

	resp, err := c.HTTPClient.Do(req)
	if err != nil {
		return "", err
	}

	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		data, _ := io.ReadAll(resp.Body)
		return "", fmt.Errorf("%d: %s", resp.StatusCode, string(data))
	}

	var apiResp IranFirewallResponse
	err = json.NewDecoder(resp.Body).Decode(&apiResp)
	if err != nil {
		return "", err
	}

	return apiResp.Response.Result, nil
}

// MACAddressLookup This tool will display the name of the company that manufactured a specific network device based on its MAC Address.
//
// URL:
//   https://api.viewdns.info/maclookup/
//
// Parameters:
//  - `mac` - the MAC address to lookup
//  - `output` - the output format required ('xml' or 'json')
//  - `apikey` - your api key
//
// GET https://api.viewdns.info/maclookup/?mac=00-05-02-34-56-78&apikey=yourapikey&output=output_type
func (c Client) MACAddressLookup(ctx context.Context, mac string) (string, error) {
	endpoint, err := c.baseURL.Parse(path.Join(c.baseURL.Path, "maclookup"))
	if err != nil {
		return "", err
	}

	query := endpoint.Query()
	query.Set("mac", mac)
	query.Set("apikey", c.apiKey)
	query.Set("output", "json")
	endpoint.RawQuery = query.Encode()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint.String(), http.NoBody)
	if err != nil {
		return "", err
	}

	resp, err := c.HTTPClient.Do(req)
	if err != nil {
		return "", err
	}

	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		data, _ := io.ReadAll(resp.Body)
		return "", fmt.Errorf("%d: %s", resp.StatusCode, string(data))
	}

	var apiResp MACAddressLookupResponse
	err = json.NewDecoder(resp.Body).Decode(&apiResp)
	if err != nil {
		return "", err
	}

	return apiResp.Response.Manufacturer, nil
}

// Ping Test how long a response from remote system takes to reach the ViewDNS server.
//
// Useful for detecting latency issues on network connections.
//
// URL:
// https://api.viewdns.info/ping/
//
// Parameters:
//  - `host` - the domain or IP address to perform a ping on
//  - `output` - the output format required ('xml' or 'json')
//  - `apikey` - your api key
//
// GET https://api.viewdns.info/ping/?host=twitter.com&apikey=yourapikey&output=output_type
func (c Client) Ping(ctx context.Context, host string) ([]Reply, error) {
	endpoint, err := c.baseURL.Parse(path.Join(c.baseURL.Path, "ping"))
	if err != nil {
		return nil, err
	}

	query := endpoint.Query()
	query.Set("host", host)
	query.Set("apikey", c.apiKey)
	query.Set("output", "json")
	endpoint.RawQuery = query.Encode()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint.String(), http.NoBody)
	if err != nil {
		return nil, err
	}

	resp, err := c.HTTPClient.Do(req)
	if err != nil {
		return nil, err
	}

	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		data, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("%d: %s", resp.StatusCode, string(data))
	}

	var apiResp PingResponse
	err = json.NewDecoder(resp.Body).Decode(&apiResp)
	if err != nil {
		return nil, err
	}

	return apiResp.Response.Replies, nil
}

// PortScanner This web based port scanner will test whether common ports are open on a server.
//
// Useful in determining if a specific service (e.g. HTTP) is up or down on a specific server.
//
// Ports scanned are: 21, 22, 23, 25, 80, 110, 139, 143, 445, 1433, 1521, 3306 and 3389
//
// URL:
//   https://api.viewdns.info/portscan/
//
// Parameters:
//  - `host` - the host to perform the port scanner on (domain or IP address)
//  - `output` - the output format required ('xml' or 'json')
//  - `apikey` - your api key
//
// GET https://api.viewdns.info/portscan/?host=viewdns.info&apikey=yourapikey&output=output_type
func (c Client) PortScanner(ctx context.Context, host string) ([]Port, error) {
	endpoint, err := c.baseURL.Parse(path.Join(c.baseURL.Path, "portscan"))
	if err != nil {
		return nil, err
	}

	query := endpoint.Query()
	query.Set("host", host)
	query.Set("apikey", c.apiKey)
	query.Set("output", "json")
	endpoint.RawQuery = query.Encode()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint.String(), http.NoBody)
	if err != nil {
		return nil, err
	}

	resp, err := c.HTTPClient.Do(req)
	if err != nil {
		return nil, err
	}

	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		data, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("%d: %s", resp.StatusCode, string(data))
	}

	var apiResp PortScannerResponse
	err = json.NewDecoder(resp.Body).Decode(&apiResp)
	if err != nil {
		return nil, err
	}

	return apiResp.Response.Ports, nil
}

// ReverseDNSLookup Find the reverse DNS entry (PTR) for a given IP. This is generally the server or host name.
//
// URL:
//   https://api.viewdns.info/reversedns/
//
// Parameters:
//  - `ip` - the IP address to retrieve the reverse DNS record for
//  - `output` - the output format required ('xml' or 'json')
//  - `apikey` - your api key
//
// GET https://api.viewdns.info/reversedns/?ip=199.59.148.10&apikey=yourapikey&output=output_type
func (c Client) ReverseDNSLookup(ctx context.Context, ip string) (string, error) {
	endpoint, err := c.baseURL.Parse(path.Join(c.baseURL.Path, "reversedns"))
	if err != nil {
		return "", err
	}

	query := endpoint.Query()
	query.Set("ip", ip)
	query.Set("apikey", c.apiKey)
	query.Set("output", "json")
	endpoint.RawQuery = query.Encode()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint.String(), http.NoBody)
	if err != nil {
		return "", err
	}

	resp, err := c.HTTPClient.Do(req)
	if err != nil {
		return "", err
	}

	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		data, _ := io.ReadAll(resp.Body)
		return "", fmt.Errorf("%d: %s", resp.StatusCode, string(data))
	}

	var apiResp ReverseDNSLookupResponse
	err = json.NewDecoder(resp.Body).Decode(&apiResp)
	if err != nil {
		return "", err
	}

	return apiResp.Response.Rdns, nil
}

// ReverseIPLookup Takes a domain or IP address and quickly shows all other domains hosted from the same server.
//
// Useful for finding phishing sites or identifying other sites on the same shared hosting server.
// By default, the first 10,000 results are returned.
//
// URL:
//   https://api.viewdns.info/reverseip/
//
// Parameters:
//  - `host` - the domain or IP address to find all hosted domains on
//  - `output` - the output format required ('xml' or 'json')
//  - `apikey` - your api key
//  - `page` - view further pages of results (e.g. '2' to view results 10,001 to 20,000) - optional
//
// GET https://api.viewdns.info/reverseip/?host=199.59.148.10&apikey=yourapikey&output=output_type
func (c Client) ReverseIPLookup(ctx context.Context, host string, page int) (*ReverseIPLookup, error) {
	endpoint, err := c.baseURL.Parse(path.Join(c.baseURL.Path, "reverseip"))
	if err != nil {
		return nil, err
	}

	query := endpoint.Query()
	query.Set("host", host)
	query.Set("apikey", c.apiKey)
	query.Set("output", "json")

	if page > 1 {
		query.Set("page", strconv.Itoa(page))
	}

	endpoint.RawQuery = query.Encode()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint.String(), http.NoBody)
	if err != nil {
		return nil, err
	}

	resp, err := c.HTTPClient.Do(req)
	if err != nil {
		return nil, err
	}

	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		data, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("%d: %s", resp.StatusCode, string(data))
	}

	var apiResp ReverseIPLookupResponse
	err = json.NewDecoder(resp.Body).Decode(&apiResp)
	if err != nil {
		return nil, err
	}

	return &apiResp.Response, nil
}

// ReverseMXLookup Takes a mail server (e.g. mail.google.com)
// and quickly shows all other domains that use the same mail server.
//
// Useful for identifying domains that are used as email aliases
//
// URL:
//   https://api.viewdns.info/reversemx/
//
// Parameters:
//  - `mx` - the mail server to query
//  - `output` - the output format required ('xml' or 'json')
//  - `apikey` - your api key
//  - `page` - view further pages of results (e.g. '2' to view results 10,001 to 20,000) - optional
//
// GET https://api.viewdns.info/reversemx/?mx=mail.google.com&apikey=yourapikey&output=output_type
func (c Client) ReverseMXLookup(ctx context.Context, mx string, page int) (*ReverseMXLookup, error) {
	endpoint, err := c.baseURL.Parse(path.Join(c.baseURL.Path, "reversemx"))
	if err != nil {
		return nil, err
	}

	query := endpoint.Query()
	query.Set("mx", mx)
	query.Set("apikey", c.apiKey)
	query.Set("output", "json")

	if page > 1 {
		query.Set("page", strconv.Itoa(page))
	}

	endpoint.RawQuery = query.Encode()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint.String(), http.NoBody)
	if err != nil {
		return nil, err
	}

	resp, err := c.HTTPClient.Do(req)
	if err != nil {
		return nil, err
	}

	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		data, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("%d: %s", resp.StatusCode, string(data))
	}

	var apiResp ReverseMXLookupResponse
	err = json.NewDecoder(resp.Body).Decode(&apiResp)
	if err != nil {
		return nil, err
	}

	return &apiResp.Response, nil
}

// ReverseNSLookup Takes a nameserver (e.g. ns.example.com) and quickly shows all other domains that share the same nameserver.
// Useful for identifying other domains that share the same web server or hosting company.
//
// URL:
//   https://api.viewdns.info/reversens/
//
// Parameters:
//  - `ns` - the nameserver to query
//  - `output` - the output format required ('xml' or 'json')
//  - `apikey` - your api key
//  - `page` - view further pages of results (e.g. '2' to view results 10,001 to 20,000) - optional
//
// GET https://api.viewdns.info/reversens/?ns=ns1.websitewelcome.com&apikey=yourapikey&output=output_type
func (c Client) ReverseNSLookup(ctx context.Context, ns string, page int) (*ReverseNSLookup, error) {
	endpoint, err := c.baseURL.Parse(path.Join(c.baseURL.Path, "reversens"))
	if err != nil {
		return nil, err
	}

	query := endpoint.Query()
	query.Set("ns", ns)
	query.Set("apikey", c.apiKey)
	query.Set("output", "json")

	if page > 1 {
		query.Set("page", strconv.Itoa(page))
	}

	endpoint.RawQuery = query.Encode()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint.String(), http.NoBody)
	if err != nil {
		return nil, err
	}

	resp, err := c.HTTPClient.Do(req)
	if err != nil {
		return nil, err
	}

	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		data, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("%d: %s", resp.StatusCode, string(data))
	}

	var apiResp ReverseNSLookupResponse
	err = json.NewDecoder(resp.Body).Decode(&apiResp)
	if err != nil {
		return nil, err
	}

	return &apiResp.Response, nil
}

// ReverseWhoisLookup This tool will allow you to find domain names owned by an individual person or company.
//
// Simply provide the email address or name of the person or company to find other domains registered using those same details.
// Returns 1,000 results at a time.
//
// Note:
//     This tool is not available to free API key users. Access is restricted to paid API keys only.
//
// URL:
//   https://api.viewdns.info/reversewhois/
//
// Parameters:
//  - `q` - the registrant name or email address to search for
//  - `output` - the output format required ('xml' or 'json')
//  - `apikey` - your api key
//  - `page` - view further pages of results (e.g. '2' to view results 1,001 to 2,000) - optional
//
// GET https://api.viewdns.info/reversewhois/?q=domain@example.com&apikey=yourapikey&output=output_type
func (c Client) ReverseWhoisLookup(ctx context.Context, q string, page int) (*ReverseWhoisLookup, error) {
	endpoint, err := c.baseURL.Parse(path.Join(c.baseURL.Path, "reversewhois"))
	if err != nil {
		return nil, err
	}

	query := endpoint.Query()
	query.Set("q", q)
	query.Set("apikey", c.apiKey)
	query.Set("output", "json")

	if page > 1 {
		query.Set("page", strconv.Itoa(page))
	}

	endpoint.RawQuery = query.Encode()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint.String(), http.NoBody)
	if err != nil {
		return nil, err
	}

	resp, err := c.HTTPClient.Do(req)
	if err != nil {
		return nil, err
	}

	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		data, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("%d: %s", resp.StatusCode, string(data))
	}

	var apiResp ReverseWhoisLookupResponse
	err = json.NewDecoder(resp.Body).Decode(&apiResp)
	if err != nil {
		return nil, err
	}

	return &apiResp.Response, nil
}

// SpamDatabaseLookup Find out if your mail server is listed in any spam databases.
//
// URL:
//   https://api.viewdns.info/spamdblookup/
//
// Parameters:
//  - `ip` - the IP address to test for spam blacklisting
//  - `output` - the output format required ('xml' or 'json')
//  - `apikey` - your api key
//
// GET https://api.viewdns.info/spamdblookup/?ip=1.2.3.4&apikey=yourapikey&output=output_type
func (c Client) SpamDatabaseLookup(ctx context.Context, ip string) ([]DB, error) {
	endpoint, err := c.baseURL.Parse(path.Join(c.baseURL.Path, "spamdblookup"))
	if err != nil {
		return nil, err
	}

	query := endpoint.Query()
	query.Set("ip", ip)
	query.Set("apikey", c.apiKey)
	query.Set("output", "json")
	endpoint.RawQuery = query.Encode()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint.String(), http.NoBody)
	if err != nil {
		return nil, err
	}

	resp, err := c.HTTPClient.Do(req)
	if err != nil {
		return nil, err
	}

	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		data, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("%d: %s", resp.StatusCode, string(data))
	}

	var apiResp SpamDatabaseLookupResponse
	err = json.NewDecoder(resp.Body).Decode(&apiResp)
	if err != nil {
		return nil, err
	}

	return apiResp.Response.Dbs, nil
}

// Traceroute Determines the series of servers that data traverses from the ViewDNS server to the specified domain name or IP address.
//
// URL:
//   https://api.viewdns.info/traceroute/
//
// Parameters:
//  - `domain` - the domain or IP address to perform a traceroute on
//  - `output` - the output format required ('xml' or 'json')
//  - `apikey` - your api key
//
// GET https://api.viewdns.info/traceroute/?domain=twitter.com&apikey=yourapikey&output=output_type
func (c Client) Traceroute(ctx context.Context, domain string) ([]Hop, error) {
	endpoint, err := c.baseURL.Parse(path.Join(c.baseURL.Path, "traceroute"))
	if err != nil {
		return nil, err
	}

	query := endpoint.Query()
	query.Set("domain", domain)
	query.Set("apikey", c.apiKey)
	query.Set("output", "json")
	endpoint.RawQuery = query.Encode()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint.String(), http.NoBody)
	if err != nil {
		return nil, err
	}

	resp, err := c.HTTPClient.Do(req)
	if err != nil {
		return nil, err
	}

	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		data, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("%d: %s", resp.StatusCode, string(data))
	}

	var apiResp TracerouteResponse
	err = json.NewDecoder(resp.Body).Decode(&apiResp)
	if err != nil {
		return nil, err
	}

	return apiResp.Response.Hops, nil
}
