# ViewDNS Go Client

A simple API Client written in Go for https://viewdns.info

API documentation: https://viewdns.info/api/

## Examples

```go
package main

import (
	"context"
	"fmt"
	"log"

	"github.com/electrologue/viewdns"
)

func main() {
	client := viewdns.NewClient("my_api_key")

	records, err := client.DNSRecordLookup(context.Background(), "example.com", "ANY")
	if err != nil {
		log.Fatal(err)
	}
	
	
	for _, record := range records {
		fmt.Println(record.Name)
	}
}
```

```go
package main

import (
	"context"
	"fmt"
	"log"

	"github.com/electrologue/viewdns"
)

func main() {
	client := viewdns.NewClient("my_api_key")

	ipHistory, err := client.IPHistory(context.Background(), "example.com")
	if err != nil {
		log.Fatal(err)
	}

	for _, history := range ipHistory {
		fmt.Println(history.Location)
	}
}
```
