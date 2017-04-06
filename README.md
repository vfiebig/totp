# totp
Simple GO TOTP compatible with Google Authenticator, based on https://www.ietf.org/rfc/rfc4226.txt

https://godoc.org/github.com/vfiebig/totp


## usage
```go
package main

import (
	"encoding/base32"
	"github.com/vfiebig/totp"
)

func main() {
	totp := totp.StdTOTP
	totp.K, _ = base32.StdEncoding.DecodeString("BASE32SECRET")

	if totp.Validate(123456) {
		// Valid token
	} else {
		// Invalid token
	}
}

```
