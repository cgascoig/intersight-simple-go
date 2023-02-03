package main

import (
	"fmt"
	"log"
	"os"

	"github.com/cgascoig/intersight-simple-go/intersight"
	"github.com/gruntwork-io/terratest/modules/random"
	"github.com/icza/dyno"
)

func main() {
	policyName := fmt.Sprintf("cg-go-ci-test-%s", random.UniqueId())
	log.Printf("Using policy name %s", policyName)

	c, err := intersight.NewClient(intersight.Config{
		KeyID:   os.Getenv("IS_KEY_ID"), // we set these explicitly as we will use the key data in env var for CI tests
		KeyData: os.Getenv("IS_KEY"),
	})
	if err != nil {
		log.Fatalf("Error: %v", err)
	}

	// Create NTP Policy
	log.Print("Creating NTP policy ...")
	body := fmt.Sprintf(`{"Name": "%s", "Enabled": true, "Organization": {"ClassId":"mo.MoRef", "ObjectType": "organization.Organization", "Selector": "Name eq 'default'"}, "NtpServers": ["1.1.1.1"]}`, policyName)
	res, err := c.Post("/api/v1/ntp/Policies", []byte(body))
	if err != nil {
		log.Fatalf("Error: %v", err)
	}

	moid, err := dyno.GetString(res, "Moid")
	if err != nil {
		log.Fatalf("Result did not contain Moid")
	}
	log.Printf("NTP policy created successfully, Moid=%s", moid)

	// Get NTP Policy
	log.Print("Getting NTP policy by moid ...")
	res, err = c.Get(fmt.Sprintf("/api/v1/ntp/Policies/%s", moid))
	if err != nil {
		log.Fatalf("Error: %v", err)
	}

	name, err := dyno.GetString(res, "Name")
	if err != nil {
		log.Fatalf("Result did not contain Name")
	}
	if name != policyName {
		log.Fatalf("Created policy name doesn't match")
	}
	log.Printf("NTP policy retrieved successfully")

	// Delete NTP Policy
	log.Printf("Deleting NTP policy ...")
	_, err = c.Delete(fmt.Sprintf("/api/v1/ntp/Policies/%s", moid))
	if err != nil {
		log.Fatalf("Error: %v", err)
	}
	log.Printf("NTP policy deleted successfully")
}
