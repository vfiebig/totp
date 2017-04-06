# totp
Simple GO TOTP

## usage
```go
import "github.com/vfiebig/totp"

totp := totp.StdTOTP
totp.K, _ = base32.StdEncoding.DecodeString("BASE32SECRET")

if totp.Validate(123456) {
  // Valid token
} else {
  // Invlid token
}
```
