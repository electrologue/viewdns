package viewdns

type Server struct {
	Location string `json:"location"`
	Value    string `json:"resultvalue"`
	Status   string `json:"resultstatus"`
}

type AbuseLookupResponse struct {
	Query struct {
		Tool   string `json:"tool"`
		Domain string `json:"domain"`
	} `json:"query"`
	Response struct {
		Abusecontact string `json:"abusecontact"`
	} `json:"response"`
}

type ChineseFirewallResponse struct {
	Query struct {
		Tool   string `json:"tool"`
		Domain string `json:"domain"`
	} `json:"query"`
	ExpectedResponse string          `json:"expectedresponse"`
	Response         ChineseFirewall `json:"v2response"`
}

type ChineseFirewall struct {
	DNSResult  DNSResult  `json:"dnsresults"`
	HTTPResult HTTPResult `json:"httpresults"`
}

type DNSResult struct {
	Servers     []Server `json:"server"`
	Summary     string   `json:"summary"`
	Description string   `json:"description"`
}

type HTTPResult struct {
	Detail      string `json:"detail"`
	Summary     string `json:"summary"`
	Description string `json:"description"`
}

type DNSPropagationCheckerResponse struct {
	Query struct {
		Tool   string `json:"tool"`
		Domain string `json:"domain"`
	} `json:"query"`
	ExpectedResponse string `json:"expectedresponse"`
	Response         struct {
		Servers []Server `json:"server"`
	} `json:"response"`
}

type DNSRecordLookupResponse struct {
	Query struct {
		Tool   string `json:"tool"`
		Domain string `json:"domain"`
		Type   string `json:"recordtype"`
	} `json:"query"`
	Response struct {
		Records []DNSRecord `json:"records"`
	} `json:"response"`
}

type DNSRecord struct {
	Name     string `json:"name"`
	TTL      string `json:"ttl"`
	Class    string `json:"class"`
	Type     string `json:"type"`
	Priority string `json:"priority"`
	Data     string `json:"data"`
}

type WhoisResponse struct {
	Query struct {
		Tool   string `json:"tool"`
		Domain string `json:"domain"`
	} `json:"query"`
	Response Whois `json:"response"`
}

type Whois struct {
	Registrant   string       `json:"registrant"`
	Registration Registration `json:"registration"`
	NameServers  []string     `json:"name_servers"`
	RawData      string       `json:"rawdata"`
}

type Registration struct {
	Created   string   `json:"created"`
	Expires   string   `json:"expires"`
	Updated   string   `json:"updated"`
	Registrar string   `json:"registrar"`
	Statuses  []string `json:"statuses"`
}

type FreeEmailLookupResponse struct {
	Query struct {
		Tool   string `json:"tool"`
		Domain string `json:"domain"`
	} `json:"query"`
	Response struct {
		Result string `json:"result"`
	} `json:"response"`
}

type GetHTTPHeadersResponse struct {
	Query struct {
		Tool   string `json:"tool"`
		Domain string `json:"domain"`
	} `json:"query"`
	Response struct {
		Headers []Header `json:"headers"`
	} `json:"response"`
}

type Header struct {
	Name  string `json:"name"`
	Value string `json:"value"`
}

type GooglePagerankCheckerResponse struct {
	Query struct {
		Tool   string `json:"tool"`
		Domain string `json:"domain"`
	} `json:"query"`
	Response struct {
		Pagerank string `json:"pagerank"`
	} `json:"response"`
}

type IPHistoryResponse struct {
	Query struct {
		Tool   string `json:"tool"`
		Domain string `json:"domain"`
	} `json:"query"`
	Response struct {
		Records []IPRecord `json:"records"`
	} `json:"response"`
}

type IPRecord struct {
	IP       string `json:"ip"`
	Location string `json:"location"`
	Owner    string `json:"owner"`
	LastSeen string `json:"lastseen"`
}

type IPLocationFinderResponse struct {
	Query struct {
		Tool string `json:"tool"`
		IP   string `json:"ip"`
	} `json:"query"`
	Response IPLocation `json:"response"`
}

type IPLocation struct {
	City        string `json:"city"`
	Zipcode     string `json:"zipcode"`
	RegionCode  string `json:"region_code"`
	RegionName  string `json:"region_name"`
	CountryCode string `json:"country_code"`
	CountryName string `json:"country_name"`
	Latitude    string `json:"latitude"`
	Longitude   string `json:"longitude"`
	GmtOffset   string `json:"gmt_offset"`
	DstOffset   string `json:"dst_offset"`
}

type IranFirewallResponse struct {
	Query struct {
		Tool    string `json:"tool"`
		SiteURL string `json:"siteurl"`
	} `json:"query"`
	Response struct {
		Result string `json:"result"`
	} `json:"response"`
}

type MACAddressLookupResponse struct {
	Query struct {
		Tool string `json:"tool"`
		Mac  string `json:"mac"`
	} `json:"query"`
	Response struct {
		Manufacturer string `json:"manufacturer"`
	} `json:"response"`
}

type PingResponse struct {
	Query struct {
		Tool string `json:"tool"`
		Host string `json:"host"`
	} `json:"query"`
	Response struct {
		Replies []Reply `json:"replys"`
	} `json:"response"`
}

type Reply struct {
	RTT string `json:"rtt"`
}

type PortScannerResponse struct {
	Query struct {
		Tool string `json:"tool"`
		Host string `json:"host"`
	} `json:"query"`
	Response struct {
		Ports []Port `json:"port"`
	} `json:"response"`
}

type Port struct {
	Number  string `json:"number"`
	Service string `json:"service"`
	Status  string `json:"status"`
}

type ReverseDNSLookupResponse struct {
	Query struct {
		Tool string `json:"tool"`
		IP   string `json:"ip"`
	} `json:"query"`
	Response struct {
		Rdns string `json:"rdns"`
	} `json:"response"`
}

type ReverseIPLookupResponse struct {
	Query struct {
		Tool string `json:"tool"`
		Host string `json:"host"`
	} `json:"query"`
	Response ReverseIPLookup `json:"response"`
}

type ReverseIPLookup struct {
	DomainCount string   `json:"domain_count"`
	Domains     []Domain `json:"domains"`
}

type Domain struct {
	Name         string `json:"name"`
	LastResolved string `json:"last_resolved"`
}

type ReverseMXLookupResponse struct {
	Query struct {
		Tool       string `json:"tool"`
		MailServer string `json:"mailserver"`
	} `json:"query"`
	Response ReverseMXLookup `json:"response"`
}

type ReverseMXLookup struct {
	DomainCount string   `json:"domain_count"`
	TotalPages  string   `json:"total_pages"`
	CurrentPage string   `json:"current_page"`
	Domains     []string `json:"domains"`
}

type ReverseNSLookupResponse struct {
	Query struct {
		Tool       string `json:"tool"`
		Nameserver string `json:"nameserver"`
	} `json:"query"`
	Response ReverseNSLookup `json:"response"`
}

type ReverseNSLookup struct {
	DomainCount string     `json:"domain_count"`
	TotalPages  string     `json:"total_pages"`
	CurrentPage string     `json:"current_page"`
	Domains     []NSDomain `json:"domains"`
}

type NSDomain struct {
	Domain string `json:"domain"`
}

type ReverseWhoisLookupResponse struct {
	Query struct {
		Tool       string `json:"tool"`
		Nameserver string `json:"nameserver"`
	} `json:"query"`
	Response ReverseWhoisLookup `json:"response"`
}

type ReverseWhoisLookup struct {
	ResultCount string  `json:"result_count"`
	TotalPages  string  `json:"total_pages"`
	CurrentPage string  `json:"current_page"`
	Matches     []Match `json:"matches"`
}

type Match struct {
	Domain      string `json:"domain"`
	CreatedDate string `json:"created_date"`
	Registrar   string `json:"registrar"`
}

type SpamDatabaseLookupResponse struct {
	Query struct {
		Tool string `json:"tool"`
		IP   string `json:"ip"`
	} `json:"query"`
	Response struct {
		Dbs []DB `json:"dbs"`
	} `json:"response"`
}

type DB struct {
	Name   string `json:"name"`
	Result string `json:"result"`
}

type TracerouteResponse struct {
	Query struct {
		Tool   string `json:"tool"`
		Domain string `json:"domain"`
	} `json:"query"`
	Response struct {
		Hops []Hop `json:"hops"`
	} `json:"response"`
}

type Hop struct {
	Number   string `json:"number"`
	Hostname string `json:"hostname"`
	IP       string `json:"ip"`
	RTT      string `json:"rtt"`
}
