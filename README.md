[![Tests](https://github.com/cgascoig/intersight-simple-go/actions/workflows/ci.yml/badge.svg)](https://github.com/cgascoig/intersight-simple-go/actions/workflows/ci.yml) 
[![GoDoc](https://godoc.org/github.com/cgascoig/intersight-simple-go?status.svg)](https://godoc.org/github.com/cgascoig/intersight-simple-go)
[![Go Report](https://goreportcard.com/badge/github.com/cgascoig/intersight-simple-go)](https://goreportcard.com/report/github.com/cgascoig/intersight-simple-go)

This module provides a simple to use client for the Intersight API. 

## Features
- Handles signature authentication and supports both v2 and v3 keys.
- Faster compile time
- Simple to use
- Automatic configuration using environment variables

## Example

```
package main

import (
	"fmt"
	"log"

	"github.com/cgascoig/intersight-simple-go/intersight"
)

func main() {
	client, err := intersight.NewClient()
	if err != nil {
		log.Fatalf("Error creating client: %v", err)
	}

	result, err := client.Get("/api/v1/ntp/Policies")
	if err != nil {
		log.Fatalf("Error in API call: %v", err)
	}

	fmt.Printf("Result: \n%v", result)
}

```