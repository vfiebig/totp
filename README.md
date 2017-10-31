# totp
Simple GO TOTP compatible with Google Authenticator, based on RFC4226

https://godoc.org/github.com/vfiebig/totp


## usage
```go
package main

import (
	"encoding/base32"
	"github.com/vfiebig/totp"
)

func main() {
	totp_inst := totp.StdTOTP
	totp_inst.K, _ = base32.StdEncoding.DecodeString("BASE32SECRET")

	if _, ok := totp_inst.Validate(123456); ok {
		// Valid token
	} else {
		// Not a valid token
	}
}

```
