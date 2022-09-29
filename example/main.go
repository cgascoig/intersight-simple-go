package main

import (
	"fmt"
	"log"
	"os"

	"github.com/cgascoig/intersight-simple-go/client"
	"github.com/icza/dyno"
)

func main() {
	c, err := client.NewClient(client.Config{
		KeyID:   os.Getenv("IS_KEYID"),
		KeyFile: os.Getenv("IS_KEYFILE"),
	})
	if err != nil {
		log.Fatalf("Error: %v", err)
	}

	res, err := c.Get("/api/v1/ntp/Policies?$count=true")
	if err != nil {
		log.Fatalf("Error: %v", err)
	}

	fmt.Printf("%v\n", res)

	count, err := dyno.GetInteger(res, "Count")
	if err != nil {
		log.Fatalf("Error: %v", err)
	}
	typ, err := dyno.GetString(res, "ObjectType")
	if err != nil {
		log.Fatalf("Error: %v", err)
	}
	fmt.Printf("Count: %d; Type: %s\n", count, typ)
}
