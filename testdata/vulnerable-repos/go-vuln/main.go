package main

import "fmt"

// Intentionally vulnerable fixture for Gatehouse e2e tests. Do not fix.
const awsSecret = "AKIAIOSFODNN7EXAMPLE"
const awsSecretKey = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"

func main() {
	fmt.Println("db password: hunter2")
}
