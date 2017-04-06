package totp

import (
	"crypto/hmac"
	"crypto/sha1"
	"encoding/binary"
	"math"
	"time"
)

// TOTP struct where K is a byte array of user key, Digit how long the token and Window the time window in seconds
type TOTP struct {
	K      []byte
	Digit  int
	Window int64
}

// Validate check if the code is correct, return true or false
func (t *TOTP) Validate(code uint64) bool {
	clock := uint64(time.Now().Unix() / t.Window)
	C := make([]byte, 8)
	binary.BigEndian.PutUint64(C, clock)

	mac := hmac.New(sha1.New, t.K)
	mac.Write(C)

	truncate := Truncate(mac.Sum(nil), t.Digit)
	if truncate != code {
		return false
	}
	return true
}

// Truncate trunc hmac as the RFC says so
func Truncate(hmacres []byte, digits int) uint64 {
	offset := uint64(hmacres[19] & 0xf)
	binCode := uint64(int(hmacres[offset]&0x7f)<<24 | int(hmacres[offset+1]&0xff)<<16 | int(hmacres[offset+2]&0xff)<<8 | int(hmacres[offset+3]&0xff))
	return uint64(binCode % uint64(math.Pow10(digits)))
}

// StdTOTP Standard TOTP
var StdTOTP = TOTP{
	Window: 30,
	Digit:  6,
}
