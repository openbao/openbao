package jwt_test

import (
	"testing"
	"time"

	"github.com/SermoDigital/jose/crypto"
	"github.com/SermoDigital/jose/jws"
	"github.com/SermoDigital/jose/jwt"
)

func TestMultipleAudienceBug_AfterMarshal(t *testing.T) {

	// Create JWS claims
	claims := jws.Claims{}
	claims.SetAudience("example.com", "api.example.com")

	token := jws.NewJWT(claims, crypto.SigningMethodHS256)
	serializedToken, _ := token.Serialize([]byte("abcdef"))

	// Unmarshal JSON
	newToken, _ := jws.ParseJWT(serializedToken)

	c := newToken.Claims()

	// Get Audience
	aud, ok := c.Audience()
	if !ok {

		// Fails
		t.Fail()
	}

	t.Logf("aud Value: %s", aud)
	t.Logf("aud Type : %T", aud)
}

func TestMultipleAudienceFix_AfterMarshal(t *testing.T) {
	// Create JWS claims
	claims := jws.Claims{}
	claims.SetAudience("example.com", "api.example.com")

	token := jws.NewJWT(claims, crypto.SigningMethodHS256)
	serializedToken, _ := token.Serialize([]byte("abcdef"))

	// Unmarshal JSON
	newToken, _ := jws.ParseJWT(serializedToken)

	c := newToken.Claims()

	// Get Audience
	aud, ok := c.Audience()
	if !ok {

		// Fails
		t.Fail()
	}

	t.Logf("aud len(): %d", len(aud))
	t.Logf("aud Value: %s", aud)
	t.Logf("aud Type : %T", aud)
}

func TestSingleAudienceFix_AfterMarshal(t *testing.T) {
	// Create JWS claims
	claims := jws.Claims{}
	claims.SetAudience("example.com")

	token := jws.NewJWT(claims, crypto.SigningMethodHS256)
	serializedToken, _ := token.Serialize([]byte("abcdef"))

	// Unmarshal JSON
	newToken, _ := jws.ParseJWT(serializedToken)
	c := newToken.Claims()

	// Get Audience
	aud, ok := c.Audience()
	if !ok {

		// Fails
		t.Fail()
	}

	t.Logf("aud len(): %d", len(aud))
	t.Logf("aud Value: %s", aud)
	t.Logf("aud Type : %T", aud)
}

func TestValidate(t *testing.T) {
	now := time.Date(2015, 1, 1, 0, 0, 0, 0, time.UTC)
	before, after := now.Add(-time.Minute), now.Add(time.Minute)
	leeway := 10 * time.Second

	exp := func(t time.Time) jwt.Claims {
		return jwt.Claims{"exp": t.Unix()}
	}
	nbf := func(t time.Time) jwt.Claims {
		return jwt.Claims{"nbf": t.Unix()}
	}

	var tests = []struct {
		desc      string
		c         jwt.Claims
		now       time.Time
		expLeeway time.Duration
		nbfLeeway time.Duration
		err       error
	}{
		// test for nbf < now <= exp
		{desc: "exp == nil && nbf == nil", c: jwt.Claims{}, now: now, err: nil},

		{desc: "now > exp", now: now, c: exp(before), err: jwt.ErrTokenIsExpired},
		{desc: "now = exp", now: now, c: exp(now), err: nil},
		{desc: "now < exp", now: now, c: exp(after), err: nil},

		{desc: "nbf < now", c: nbf(before), now: now, err: nil},
		{desc: "nbf = now", c: nbf(now), now: now, err: jwt.ErrTokenNotYetValid},
		{desc: "nbf > now", c: nbf(after), now: now, err: jwt.ErrTokenNotYetValid},

		// test for nbf-x < now <= exp+y
		{desc: "now < exp+x", now: now.Add(leeway - time.Second), expLeeway: leeway, c: exp(now), err: nil},
		{desc: "now = exp+x", now: now.Add(leeway), expLeeway: leeway, c: exp(now), err: nil},
		{desc: "now > exp+x", now: now.Add(leeway + time.Second), expLeeway: leeway, c: exp(now), err: jwt.ErrTokenIsExpired},

		{desc: "nbf-x > now", c: nbf(now), nbfLeeway: leeway, now: now.Add(-leeway + time.Second), err: nil},
		{desc: "nbf-x = now", c: nbf(now), nbfLeeway: leeway, now: now.Add(-leeway), err: jwt.ErrTokenNotYetValid},
		{desc: "nbf-x < now", c: nbf(now), nbfLeeway: leeway, now: now.Add(-leeway - time.Second), err: jwt.ErrTokenNotYetValid},
	}

	for i, tt := range tests {
		if got, want := tt.c.Validate(tt.now, tt.expLeeway, tt.nbfLeeway), tt.err; got != want {
			t.Errorf("%d - %q: got %v want %v", i, tt.desc, got, want)
		}
	}
}

func TestGetAndSetTime(t *testing.T) {
	now := time.Now()
	nowUnix := now.Unix()
	c := jwt.Claims{
		"int":     int(nowUnix),
		"int32":   int32(nowUnix),
		"int64":   int64(nowUnix),
		"uint":    uint(nowUnix),
		"uint32":  uint32(nowUnix),
		"uint64":  uint64(nowUnix),
		"float64": float64(nowUnix),
	}
	c.SetTime("setTime", now)
	for k := range c {
		v, ok := c.GetTime(k)
		if got, want := v, time.Unix(nowUnix, 0); !ok || !got.Equal(want) {
			t.Errorf("%s: got %v want %v", k, got, want)
		}
	}
}

// TestTimeValuesThroughJSON verifies that the time values
// that are set via the Set{IssuedAt,NotBefore,Expiration}()
// methods can actually be parsed back
func TestTimeValuesThroughJSON(t *testing.T) {
	now := time.Unix(time.Now().Unix(), 0)

	c := jws.Claims{}
	c.SetIssuedAt(now)
	c.SetNotBefore(now)
	c.SetExpiration(now)

	// serialize to JWT
	tok := jws.NewJWT(c, crypto.SigningMethodHS256)
	b, err := tok.Serialize([]byte("key"))
	if err != nil {
		t.Fatal(err)
	}

	// parse the JWT again
	tok2, err := jws.ParseJWT(b)
	if err != nil {
		t.Fatal(err)
	}
	c2 := tok2.Claims()

	iat, ok1 := c2.IssuedAt()
	nbf, ok2 := c2.NotBefore()
	exp, ok3 := c2.Expiration()
	if !ok1 || !ok2 || !ok3 {
		t.Fatal("got false want true")
	}

	if got, want := iat, now; !got.Equal(want) {
		t.Errorf("%s: got %v want %v", "iat", got, want)
	}
	if got, want := nbf, now; !got.Equal(want) {
		t.Errorf("%s: got %v want %v", "nbf", got, want)
	}
	if got, want := exp, now; !got.Equal(want) {
		t.Errorf("%s: got %v want %v", "exp", got, want)
	}
}
