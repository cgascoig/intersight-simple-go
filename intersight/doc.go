// Package intersight provides a simple to use client for the Intersight API.
// It handles signature authentication and supports both v2 and v3 keys.
//
// Simple example to get NTP policies
//
//	func Example() {
//		client, _ := intersight.NewClient()
//
//		result, _ := client.Get("/api/v1/ntp/Policies")
//
//		fmt.Printf("Result: \n%v", result)
//	}
package intersight
