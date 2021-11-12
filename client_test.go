package viewdns

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func setupTest(t *testing.T) (*Client, *http.ServeMux) {
	t.Helper()

	mux := http.NewServeMux()

	server := httptest.NewServer(mux)
	t.Cleanup(server.Close)

	client := NewClient("secret")
	client.HTTPClient = server.Client()
	client.baseURL, _ = url.Parse(server.URL)

	return client, mux
}

func testHandler(filename string) http.HandlerFunc {
	return func(rw http.ResponseWriter, req *http.Request) {
		if req.Method != http.MethodGet {
			http.Error(rw, fmt.Sprintf("unsupported method: %s", req.Method), http.StatusMethodNotAllowed)
			return
		}

		file, err := os.Open(filepath.Join("fixtures", filename))
		if err != nil {
			http.Error(rw, err.Error(), http.StatusInternalServerError)
			return
		}

		defer func() { _ = file.Close() }()

		_, err = io.Copy(rw, file)
		if err != nil {
			http.Error(rw, err.Error(), http.StatusInternalServerError)
			return
		}
	}
}

func TestClient_AbuseContactLookup(t *testing.T) {
	client, mux := setupTest(t)

	mux.HandleFunc("/abuselookup", testHandler("AbuseContactLookup.json"))

	address, err := client.AbuseLookup(context.Background(), "example.com")
	require.NoError(t, err)

	assert.Equal(t, "abuse@twitter.com", address)
}

func TestClient_ChineseFirewallTest(t *testing.T) {
	client, mux := setupTest(t)

	mux.HandleFunc("/chinesefirewall", testHandler("ChineseFirewallTest.json"))

	data, err := client.ChineseFirewall(context.Background(), "example.com")
	require.NoError(t, err)

	expected := &ChineseFirewall{
		DNSResult: DNSResult{
			Servers: []Server{
				{Location: "Beijing", Value: "174.36.85.72", Status: "ok"},
				{Location: "Shenzen", Value: "174.36.85.72", Status: "ok"},
				{Location: "Inner Mongolia", Value: "174.36.85.72", Status: "ok"},
				{Location: "Heilongjiang Province", Value: "174.36.85.72", Status: "ok"},
				{Location: "Yunnan Province", Value: "174.36.85.72", Status: "ok"},
			},
			Summary:     "visible",
			Description: "All servers were able to reach your site at the correct IP address.  This means that the hostname itself is accessible from within mainland China.",
		},
		HTTPResult: HTTPResult{
			Detail:      "HTTP/1.1 200 OK",
			Summary:     "ok",
			Description: "This URL appears to be accessible from mainland China.",
		},
	}

	assert.Equal(t, expected, data)
}

func TestClient_DNSRecordLookup(t *testing.T) {
	client, mux := setupTest(t)

	mux.HandleFunc("/dnsrecord", testHandler("DNSRecordLookup.json"))

	data, err := client.DNSRecordLookup(context.Background(), "example.com", "ANY")
	require.NoError(t, err)

	expected := []DNSRecord{
		{Name: "twitter.com.", TTL: "600", Class: "IN", Type: "MX", Priority: "10", Data: "aspmx.l.google.com."},
		{Name: "twitter.com.", TTL: "600", Class: "IN", Type: "MX", Priority: "20", Data: "alt1.aspmx.l.google.com."},
		{Name: "twitter.com.", TTL: "600", Class: "IN", Type: "MX", Priority: "20", Data: "alt2.aspmx.l.google.com."},
		{Name: "twitter.com.", TTL: "600", Class: "IN", Type: "MX", Priority: "30", Data: "ASPMX2.GOOGLEMAIL.com."},
		{Name: "twitter.com.", TTL: "600", Class: "IN", Type: "MX", Priority: "30", Data: "ASPMX3.GOOGLEMAIL.com."},
	}

	assert.Equal(t, expected, data)
}

func TestClient_GetHTTPHeaders(t *testing.T) {
	client, mux := setupTest(t)

	mux.HandleFunc("/httpheaders", testHandler("GetHTTPHeaders.json"))

	data, err := client.GetHTTPHeaders(context.Background(), "example.com")
	require.NoError(t, err)

	expected := []Header{
		{Name: "http_status", Value: "301"},
		{Name: "connection", Value: "close"},
		{Name: "content-length", Value: "0"},
		{Name: "date", Value: "Mon, 12 Jan 2015 23:42:16 UTC"},
		{Name: "location", Value: "https://twitter.com/"},
		{Name: "server", Value: "tsa_a"},
		{Name: "set-cookie", Value: "guest_id=v1%3A142110612345448134; Domain=.twitter.com; Path=/; Expires=Wed, 11-Jan-2017 23:42:16 UTC"},
		{Name: "x-connection-hash", Value: "feb175daf57faabcde308af8372f0d8d"},
		{Name: "x-response-time", Value: "2"},
	}

	assert.Equal(t, expected, data)
}

func TestClient_IPHistory(t *testing.T) {
	client, mux := setupTest(t)

	mux.HandleFunc("/iphistory", testHandler("IPHistory.json"))

	data, err := client.IPHistory(context.Background(), "example.com")
	require.NoError(t, err)

	expected := []IPRecord{
		{IP: "93.184.216.34", Location: "United States", Owner: "NETBLK-03-EU-93-184-216-0-24", LastSeen: "2016-09-13"},
		{IP: "93.184.216.119", Location: "United States", Owner: "NETBLK-03-EU-93-184-216-0-24", LastSeen: "2014-12-09"},
		{IP: "192.0.43.10", Location: "Los Angeles - United States", Owner: "ICANN", LastSeen: "2013-07-09"},
		{IP: "192.0.32.10", Location: "Los Angeles - United States", Owner: "ICANN", LastSeen: "2011-06-05"},
	}

	assert.Equal(t, expected, data)
}

func TestClient_IranFirewallTest(t *testing.T) {
	client, mux := setupTest(t)

	mux.HandleFunc("/iranfirewall", testHandler("IranFirewallTest.json"))

	data, err := client.IranFirewall(context.Background(), "example.com")
	require.NoError(t, err)

	expected := "ok"

	assert.Equal(t, expected, data)
}

func TestClient_Ping(t *testing.T) {
	client, mux := setupTest(t)

	mux.HandleFunc("/ping", testHandler("Ping.json"))

	data, err := client.Ping(context.Background(), "example.com")
	require.NoError(t, err)

	expected := []Reply{
		{RTT: "32.5 ms"},
		{RTT: "36.2 ms"},
		{RTT: "30.8 ms"},
		{RTT: "36.6 ms"},
	}

	assert.Equal(t, expected, data)
}

func TestClient_ReverseDNSLookup(t *testing.T) {
	client, mux := setupTest(t)

	mux.HandleFunc("/reversedns", testHandler("ReverseDNSLookup.json"))

	data, err := client.ReverseDNSLookup(context.Background(), "example.com")
	require.NoError(t, err)

	expected := "r-199-59-148-10.twttr.com"

	assert.Equal(t, expected, data)
}

func TestClient_ReverseMXLookup(t *testing.T) {
	client, mux := setupTest(t)

	mux.HandleFunc("/reversemx", testHandler("ReverseMXLookup.json"))

	data, err := client.ReverseMXLookup(context.Background(), "example.com", 1)
	require.NoError(t, err)

	expected := &ReverseMXLookup{
		DomainCount: "818",
		TotalPages:  "1",
		CurrentPage: "1",
		Domains: []string{
			"090803.com", "1sthealthcare.net", "1sthealthsystems.com", "2redl.in",
			"44825263.com", "65red1.com", "800.digital", "aboutyoufitness.com",
			"academyhill.org", "acbergula.org", "accuweight-1014.com",
		},
	}

	assert.Equal(t, expected, data)
}

func TestClient_ReverseWhoisLookup(t *testing.T) {
	client, mux := setupTest(t)

	mux.HandleFunc("/reversewhois", testHandler("ReverseWhoisLookup.json"))

	data, err := client.ReverseWhoisLookup(context.Background(), "example.com", 1)
	require.NoError(t, err)

	expected := &ReverseWhoisLookup{
		ResultCount: "6",
		TotalPages:  "1",
		CurrentPage: "1",
		Matches: []Match{
			{Domain: "chibrary.com", CreatedDate: "2011-11-13", Registrar: "NAME.COM, INC."},
			{Domain: "chibrary.net", CreatedDate: "2011-11-13", Registrar: "NAME.COM, INC."},
			{Domain: "chibrary.org", CreatedDate: "2011-11-13", Registrar: "NAME.COM, LLC (R1288-LROR)"},
			{Domain: "geekmelange.com", CreatedDate: "2013-04-02", Registrar: "NAME.COM, INC."},
			{Domain: "taskforcetaro.com", CreatedDate: "2013-03-11", Registrar: "NAME.COM, INC."},
			{Domain: "taskforcetrinity.com", CreatedDate: "2012-05-22", Registrar: "NAME.COM, INC."},
		},
	}

	assert.Equal(t, expected, data)
}

func TestClient_Traceroute(t *testing.T) {
	client, mux := setupTest(t)

	mux.HandleFunc("/traceroute", testHandler("Traceroute.json"))

	data, err := client.Traceroute(context.Background(), "example.com")
	require.NoError(t, err)

	expected := []Hop{
		{Number: "1", Hostname: "obfuscated.internal.network.com", IP: "0.0.0.0", RTT: "0.000"},
		{Number: "2", Hostname: "obfuscated.internal.network.com", IP: "0.0.0.0", RTT: "1.000"},
		{Number: "3", Hostname: "v995.core1.sjc1.he.net", IP: "64.71.150.21", RTT: "7.580"},
		{Number: "4", Hostname: "10gigabitethernet2-1.core1.sjc2.he.net", IP: "72.52.92.118", RTT: "0.706"},
		{Number: "5", Hostname: "eqix2.cr2.sjc2.twttr.com", IP: "206.223.116.101", RTT: "1.937"},
		{Number: "6", Hostname: "xe-11-0-0.smf1-er1.twttr.com", IP: "199.16.159.51", RTT: "13.743"},
		{Number: "7", Hostname: "r-199-59-148-10.twttr.com", IP: "199.59.148.10", RTT: "13.249"},
	}

	assert.Equal(t, expected, data)
}

func TestClient_DNSPropagationChecker(t *testing.T) {
	client, mux := setupTest(t)

	mux.HandleFunc("/propagation", testHandler("DNSPropagationChecker.json"))

	data, err := client.DNSPropagationChecker(context.Background(), "example.com")
	require.NoError(t, err)

	expected := []Server{
		{Location: "Bangkok, Thailand", Value: "205.204.70.252", Status: "ok"},
		{Location: "Auckland, New Zealand", Value: "205.204.70.252", Status: "ok"},
		{Location: "Gent, Belgium", Value: "205.204.70.252", Status: "ok"},
		{Location: "Toronto, Canada", Value: "205.204.70.252", Status: "ok"},
		{Location: "Paris, France", Value: "205.204.70.252", Status: "ok"},
		{Location: "Echterdingen, Germany", Value: "205.204.70.252", Status: "ok"},
		{Location: "Arizona, United States", Value: "205.204.70.252", Status: "ok"},
		{Location: "New York, United States", Value: "205.204.70.252", Status: "ok"},
		{Location: "Oklahoma, United States", Value: "205.204.70.252", Status: "ok"},
		{Location: "San Francisco, United States", Value: "205.204.70.252", Status: "ok"},
		{Location: "Washington DC, United States", Value: "205.204.70.252", Status: "ok"},
		{Location: "Melbourne, Australia", Value: "205.204.70.252", Status: "ok"},
		{Location: "Sydney, Australia", Value: "205.204.70.252", Status: "ok"},
		{Location: "Beijing, China", Value: "205.204.70.252", Status: "ok"},
		{Location: "Tokyo, Japan", Value: "205.204.70.252", Status: "ok"},
		{Location: "Monterrey, Mexico", Value: "205.204.70.252", Status: "ok"},
		{Location: "Johannesburg, South Africa", Value: "205.204.70.252", Status: "ok"},
		{Location: "Moscow, Russia", Value: "205.204.70.252", Status: "ok"},
		{Location: "Manchester, United Kingdom", Value: "205.204.70.252", Status: "ok"},
	}

	assert.Equal(t, expected, data)
}

func TestClient_FreeEmailLookup(t *testing.T) {
	client, mux := setupTest(t)

	mux.HandleFunc("/freeemail", testHandler("FreeEmailLookup.json"))

	data, err := client.FreeEmailLookup(context.Background(), "example.com")
	require.NoError(t, err)

	expected := "This domain DOES NOT appear to provide free email addresses."

	assert.Equal(t, expected, data)
}

func TestClient_GooglePagerankChecker(t *testing.T) {
	client, mux := setupTest(t)

	mux.HandleFunc("/pagerank", testHandler("GooglePagerankChecker.json"))

	data, err := client.GooglePagerankChecker(context.Background(), "example.com")
	require.NoError(t, err)

	expected := "10"

	assert.Equal(t, expected, data)
}

func TestClient_IPLocationFinder(t *testing.T) {
	client, mux := setupTest(t)

	mux.HandleFunc("/iplocation", testHandler("IPLocationFinder.json"))

	data, err := client.IPLocationFinder(context.Background(), "10.10.10.10")
	require.NoError(t, err)

	expected := &IPLocation{
		City:        "Columbus",
		Zipcode:     "43218",
		RegionCode:  "OH",
		RegionName:  "Ohio",
		CountryCode: "US",
		CountryName: "United States",
		Latitude:    "39.9968",
		Longitude:   "-82.9882",
	}

	assert.Equal(t, expected, data)
}

func TestClient_MACAddressLookup(t *testing.T) {
	client, mux := setupTest(t)

	mux.HandleFunc("/maclookup", testHandler("MACAddressLookup.json"))

	data, err := client.MACAddressLookup(context.Background(), "00-05-02-34-56-78")
	require.NoError(t, err)

	expected := "APPLE COMPUTER - 20650 VALLEY GREEN DRIVE - CUPERTINO CA 95014 - UNITED STATES"

	assert.Equal(t, expected, data)
}

func TestClient_PortScanner(t *testing.T) {
	client, mux := setupTest(t)

	mux.HandleFunc("/portscan", testHandler("PortScanner.json"))

	data, err := client.PortScanner(context.Background(), "example.com")
	require.NoError(t, err)

	expected := []Port{
		{Number: "21", Service: "FTP", Status: "closed"},
		{Number: "22", Service: "SSH", Status: "closed"},
		{Number: "23", Service: "Telnet", Status: "closed"},
		{Number: "25", Service: "SMTP", Status: "closed"},
		{Number: "80", Service: "HTTP", Status: "open"},
		{Number: "110", Service: "POP3", Status: "closed"},
		{Number: "139", Service: "NETBIOS", Status: "closed"},
		{Number: "143", Service: "IMAP", Status: "closed"},
		{Number: "443", Service: "HTTPS", Status: "closed"},
		{Number: "445", Service: "SMB", Status: "closed"},
		{Number: "1433", Service: "MSSQL", Status: "closed"},
		{Number: "1521", Service: "ORACLE", Status: "closed"},
		{Number: "3306", Service: "MySQL", Status: "closed"},
		{Number: "3389", Service: "Remote Desktop", Status: "closed"},
	}

	assert.Equal(t, expected, data)
}

func TestClient_ReverseIPLookup(t *testing.T) {
	client, mux := setupTest(t)

	mux.HandleFunc("/reverseip", testHandler("ReverseIPLookup.json"))

	data, err := client.ReverseIPLookup(context.Background(), "10.10.10.10", 1)
	require.NoError(t, err)

	expected := &ReverseIPLookup{
		DomainCount: "4",
		Domains: []Domain{
			{Name: "gezwitscher.com", LastResolved: "2011-04-04"},
			{Name: "twitter.com", LastResolved: "2011-04-04"},
			{Name: "twitterfriendblaster.com", LastResolved: "2012-01-11"},
			{Name: "twttr.com", LastResolved: "2012-02-21"},
		},
	}

	assert.Equal(t, expected, data)
}

func TestClient_ReverseNSLookup(t *testing.T) {
	client, mux := setupTest(t)

	mux.HandleFunc("/reversens", testHandler("ReverseNSLookup.json"))

	data, err := client.ReverseNSLookup(context.Background(), "ns.example.com", 1)
	require.NoError(t, err)

	expected := &ReverseNSLookup{
		DomainCount: "10897",
		TotalPages:  "2",
		CurrentPage: "1",
		Domains: []NSDomain{
			{Domain: "0ctastore.com"},
			{Domain: "100-dollars-4-laptop-computer-repairs-570-457-6610.com"},
			{Domain: "1024project.org"},
			{Domain: "104dtd.org"},
			{Domain: "10gbpsservers.com"},
			{Domain: "10parrots.com"},
			{Domain: "11thcommandmentrecords.info"},
			{Domain: "11thcommandmentrecords.org"},
		},
	}

	assert.Equal(t, expected, data)
}

func TestClient_SpamDatabaseLookup(t *testing.T) {
	client, mux := setupTest(t)

	mux.HandleFunc("/spamdblookup", testHandler("SpamDatabaseLookup.json"))

	data, err := client.SpamDatabaseLookup(context.Background(), "10.10.10.10")
	require.NoError(t, err)

	expected := []DB{
		{Name: "b.barracudacentral.org", Result: "ok"},
		{Name: "bl.deadbeef.com", Result: "ok"},
		{Name: "bl.emailbasura.org", Result: "ok"},
		{Name: "bl.spamcop.net", Result: "ok"},
		{Name: "blacklist.woody.ch", Result: "ok"},
		{Name: "cbl.abuseat.org", Result: "ok"},
		{Name: "combined.rbl.msrbl.net", Result: "ok"},
		{Name: "db.wpbl.info", Result: "ok"},
		{Name: "dbl.spamhaus.org", Result: "ok"},
		{Name: "dnsbl.ahbl.org", Result: "ok"},
		{Name: "dnsbl.cyberlogic.net", Result: "ok"},
		{Name: "dnsbl.njabl.org", Result: "ok"},
		{Name: "dnsbl.sorbs.net", Result: "ok"},
		{Name: "dnsbl-3.uceprotect.net", Result: "ok"},
		{Name: "drone.abuse.ch", Result: "ok"},
		{Name: "http.dnsbl.sorbs.net", Result: "ok"},
		{Name: "httpbl.abuse.ch", Result: "ok"},
		{Name: "images.rbl.msrbl.net", Result: "ok"},
		{Name: "ips.backscatterer.org", Result: "ok"},
		{Name: "nomail.rhsbl.sorbs.net", Result: "ok"},
		{Name: "pbl.spamhaus.org", Result: "ok"},
		{Name: "phishing.rbl.msrbl.net", Result: "ok"},
		{Name: "sbl.spamhaus.org", Result: "ok"},
		{Name: "smtp.dnsbl.sorbs.net", Result: "ok"},
		{Name: "socks.dnsbl.sorbs.net", Result: "ok"},
		{Name: "spam.dnsbl.sorbs.net", Result: "ok"},
		{Name: "spam.rbl.msrbl.net", Result: "ok"},
		{Name: "spam.spamrats.com", Result: "ok"},
		{Name: "ubl.unsubscore.com", Result: "ok"},
		{Name: "virus.rbl.msrbl.net", Result: "ok"},
		{Name: "web.dnsbl.sorbs.net", Result: "ok"},
		{Name: "xbl.spamhaus.org", Result: "ok"},
		{Name: "zen.spamhaus.org", Result: "ok"},
		{Name: "zombie.dnsbl.sorbs.net", Result: "ok"},
	}

	assert.Equal(t, expected, data)
}

func TestClient_Whois(t *testing.T) {
	client, mux := setupTest(t)

	mux.HandleFunc("/whois", testHandler("Whois.json"))

	data, err := client.Whois(context.Background(), "example.com")
	require.NoError(t, err)

	expected := &Whois{
		Registrant: "Twitter, Inc",
		Registration: Registration{
			Created:   "2011-08-31",
			Expires:   "2019-01-22",
			Updated:   "2011-08-30",
			Registrar: "MELBOURNE IT, LTD. D/B/A INTERNET NAMES WORLDWIDE",
			Statuses:  []string{"clientTransferProhibited"},
		},
		NameServers: []string{"ns1.p34.dynect.net (208.78.70.34)", "ns2.p34.dynect.net (204.13.250.34)", "ns3.p34.dynect.net (208.78.71.34)", "ns4.p34.dynect.net (204.13.251.34)"},
		RawData:     "\\nDomain Name.......... twitter.com\\n  Creation Date........ 2000-01-22\\nRegistration Date.... 2011-08-31\\n  Expiry Date.......... 2019-01-22\\n  OrganizationName.... Twitter, Inc.\\n  Organization Address. 795 Folsom Street\\n  Organization Address.Suite 600\\n  Organization Address. San Francisco\\n  Organization Address. 94107\\nOrganization Address. CA\\n  Organization Address. UNITED STATES\\n\\nAdmin Name...........Domain Admin\\n  Admin Address........ 795 Folsom Street\\n  Admin Address........ Suite 600\\n  Admin Address........ San Francisco\\n  Admin Address........ 94107\\n  Admin Address........ CA\\n  Admin Address........ UNITED STATES\\n  Admin Email..........admin@melbourneitdbs.com\\n  Admin Phone.......... +415.2229670\\n  Admin Fax............+415.2220922\\n\\nTech Name............ Tech Admin\\n  Tech Address......... 795 FolsomStreet\\n  Tech Address......... Suite 600\\n  Tech Address......... San Francisco\\n  TechAddress......... 94107\\n  Tech Address......... CA\\n  Tech Address......... UNITED STATES\\nTech Email........... domains-tech@twitter.com\\n  Tech Phone........... +415.2229670\\nTech Fax............. +415.2220922\\n  Name Server.......... NS2.P34.DYNECT.NET\\n  NameServer.......... NS3.P34.DYNECT.NET\\n  Name Server.......... NS4.P34.DYNECT.NET\\n  NameServer.......... NS1.P34.DYNECT.NET\\n\\n\\n",
	}

	assert.Equal(t, expected, data)
}
