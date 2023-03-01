//go:build passauth

package main

func init() {
      features["password"] = genHostKey
}
