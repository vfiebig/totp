# totp
Simple GO TOTP compatible with Google Authenticator

## usage
```go
package main

import (
	"encoding/base32"
	"fmt"

	"github.com/vfiebig/totp"
)

func main() {
	totp := totp.StdTOTP
	totp.K, _ = base32.StdEncoding.DecodeString("BASE32SECRET")

	if totp.Validate(123456) {
		fmt.Println("Valid token")
	} else {
		fmt.Println("Invalid token")
	}
}

```
