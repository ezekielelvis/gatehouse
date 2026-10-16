package main

// Intentionally planted secrets for Gatehouse's e2e tests. DO NOT "fix" —
// these exist so a scan has something real to find.
var config = map[string]string{
	"aws_secret_access_key": "wJalrXUtnFEMI/K7MDENG/bPxRfiCYz9876543210Ab",
	"db_password":           "s3cr3t-Pr0duction-Passw0rd-do-not-use",
}
