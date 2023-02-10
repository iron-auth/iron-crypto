package str_test

import (
	"reflect"
	"testing"
	"time"

	"github.com/iron-auth/iron-crypto/ironerrors"
	"github.com/iron-auth/iron-crypto/str"
	a "github.com/james-elicx/go-utils/assert"
)

func TestString(t *testing.T) {
	t.Parallel()

	value, err := str.FromObject("Hello World!")

	a.Equals(t, err, nil)
	a.Equals(t, value, "\"Hello World!\"")

	newValue, err := str.ToObject[string](value)

	a.Equals(t, err, nil)
	a.Equals(t, newValue, "Hello World!")
}

func TestInt(t *testing.T) {
	t.Parallel()

	value, err := str.FromObject(123)

	a.Equals(t, err, nil)
	a.Equals(t, value, "123")

	newValue, err := str.ToObject[int](value)

	a.Equals(t, err, nil)
	a.Equals(t, newValue, 123)
}

func TestFloat(t *testing.T) {
	t.Parallel()

	value, err := str.FromObject(123.456)

	a.Equals(t, err, nil)
	a.Equals(t, value, "123.456")

	newValue, err := str.ToObject[float64](value)

	a.Equals(t, err, nil)
	a.Equals(t, newValue, 123.456)
}

func TestBool(t *testing.T) {
	t.Parallel()

	value, err := str.FromObject(true)

	a.Equals(t, err, nil)
	a.Equals(t, value, "true")

	newValue, err := str.ToObject[bool](value)

	a.Equals(t, err, nil)
	a.Equals(t, newValue, true)
}

func TestMap(t *testing.T) {
	t.Parallel()

	value, err := str.FromObject(map[string]interface{}{
		"hello": "world",
		"foo":   "bar",
	})

	a.Equals(t, err, nil)
	a.Equals(t, value, "{\"foo\":\"bar\",\"hello\":\"world\"}")

	newValue, err := str.ToObject[map[string]interface{}](value)

	a.Equals(t, err, nil)
	a.Equals(t, reflect.DeepEqual(newValue, map[string]interface{}{
		"hello": "world",
		"foo":   "bar",
	}), true)
}

func TestArray(t *testing.T) {
	t.Parallel()

	value, err := str.FromObject([]interface{}{
		"hello",
		"world",
	})

	a.Equals(t, err, nil)
	a.Equals(t, value, "[\"hello\",\"world\"]")

	newValue, err := str.ToObject[[]interface{}](value)

	a.Equals(t, err, nil)
	a.Equals(t, reflect.DeepEqual(newValue, []interface{}{
		"hello",
		"world",
	}), true)
}

type basicStruct struct {
	Text  string  `json:"text"`
	Num   int     `json:"number"`
	Float float64 `json:"float"`
	Bool  bool    `json:"bool"`
}

type complexStruct struct {
	Text        string
	TextArray   []string
	Array       []basicStruct
	Map         map[string]basicStruct
	BasicStruct basicStruct
	Int64       int64
	Duration    time.Duration
	Date        time.Time
	NullArray   []string
	ByteArray   []byte
}

var (
	basicStructValue = basicStruct{
		Text:  "hello",
		Num:   123,
		Float: 123.456,
		Bool:  true,
	}
	basicStructString = "{\"text\":\"hello\",\"number\":123,\"float\":123.456,\"bool\":true}"

	complexStructValue = complexStruct{
		Text:        "hello",
		TextArray:   []string{"hello", "world"},
		Array:       []basicStruct{{Text: "hello"}, {Text: "world"}},
		Map:         map[string]basicStruct{"hello": {Text: "world"}, "world": basicStructValue},
		BasicStruct: basicStruct{Text: "hello"},
		Int64:       123,
		Duration:    123 * time.Second,
		Date:        time.Date(2016, 1, 1, 0, 0, 0, 0, time.UTC),
		NullArray:   nil,
		ByteArray:   []byte("hello"),
	}
	complexStructString = "{\"Text\":\"hello\",\"TextArray\":[\"hello\",\"world\"],\"Array\":[{\"text\":\"hello\",\"number\":0,\"float\":0,\"bool\":false},{\"text\":\"world\",\"number\":0,\"float\":0,\"bool\":false}],\"Map\":{\"hello\":{\"text\":\"world\",\"number\":0,\"float\":0,\"bool\":false},\"world\":{\"text\":\"hello\",\"number\":123,\"float\":123.456,\"bool\":true}},\"BasicStruct\":{\"text\":\"hello\",\"number\":0,\"float\":0,\"bool\":false},\"Int64\":123,\"Duration\":123000000000,\"Date\":\"2016-01-01T00:00:00Z\",\"NullArray\":null,\"ByteArray\":\"aGVsbG8=\"}"

	complexStructValuePartial = complexStruct{
		Text:      "hello",
		TextArray: []string{"hello", "world"},
		Map:       map[string]basicStruct{"hello": {Text: "world"}, "world": basicStructValue},
		Date:      time.Date(2016, 1, 1, 0, 0, 0, 0, time.UTC),
		NullArray: nil,
		ByteArray: []byte("hello"),
	}
	complexStructStringPartialTo   = "{\"Text\":\"hello\",\"TextArray\":[\"hello\",\"world\"],\"Map\":{\"hello\":{\"text\":\"world\",\"number\":0,\"float\":0,\"bool\":false},\"world\":{\"text\":\"hello\",\"number\":123,\"float\":123.456,\"bool\":true}},\"Date\":\"2016-01-01T00:00:00Z\",\"NullArray\":null,\"ByteArray\":\"aGVsbG8=\"}"
	complexStructStringPartialFrom = "{\"Text\":\"hello\",\"TextArray\":[\"hello\",\"world\"],\"Array\":null,\"Map\":{\"hello\":{\"text\":\"world\",\"number\":0,\"float\":0,\"bool\":false},\"world\":{\"text\":\"hello\",\"number\":123,\"float\":123.456,\"bool\":true}},\"BasicStruct\":{\"text\":\"\",\"number\":0,\"float\":0,\"bool\":false},\"Int64\":0,\"Duration\":0,\"Date\":\"2016-01-01T00:00:00Z\",\"NullArray\":null,\"ByteArray\":\"aGVsbG8=\"}"
)

func TestBasicStruct(t *testing.T) {
	t.Parallel()

	value, err := str.FromObject(basicStructValue)

	a.Equals(t, err, nil)
	a.Equals(t, value, basicStructString)

	newValue, err := str.ToObject[basicStruct](value)

	a.Equals(t, err, nil)
	a.Equals(t, reflect.DeepEqual(newValue, basicStructValue), true)
}

func TestComplexStruct(t *testing.T) {
	t.Parallel()

	value, err := str.FromObject(complexStructValue)

	a.Equals(t, err, nil)
	a.Equals(t, value, complexStructString)

	newValue, err := str.ToObject[complexStruct](value)

	a.Equals(t, err, nil)
	a.Equals(t, reflect.DeepEqual(newValue, complexStructValue), true)
}

func TestPartial(t *testing.T) {
	t.Parallel()

	value, err := str.FromObject(complexStructValuePartial)

	a.Equals(t, err, nil)
	a.Equals(t, value, complexStructStringPartialFrom)

	newValue, err := str.ToObject[complexStruct](complexStructStringPartialTo)

	a.Equals(t, err, nil)
	a.Equals(t, reflect.DeepEqual(newValue, complexStructValuePartial), true)
}

func TestNullInStruct(t *testing.T) {
	t.Parallel()

	newValue, err := str.ToObject[basicStruct]("null")

	a.Equals(t, err, nil)
	a.Equals(t, reflect.DeepEqual(newValue, basicStruct{}), true)

	newValue, err = str.ToObject[basicStruct]("{\"text\":null,\"number\":null}")

	a.Equals(t, err, nil)
	a.Equals(t, reflect.DeepEqual(newValue, basicStruct{}), true)
}

func TestUnmarshalFailsWithUndefined(t *testing.T) {
	t.Parallel()

	_, err := str.ToObject[basicStruct]("undefined")

	a.EqualsError(t, err, ironerrors.ErrUnmarshallingObject)
}

func TestMarshalFailsWithChannel(t *testing.T) {
	t.Parallel()

	_, err := str.FromObject(make(chan int))

	a.EqualsError(t, err, ironerrors.ErrMarshallingObject)
}
