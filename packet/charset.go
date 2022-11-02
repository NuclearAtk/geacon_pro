package packet

import (
	"bytes"
	"golang.org/x/text/encoding/simplifiedchinese"
	"golang.org/x/text/transform"
	"io/ioutil"
	"unicode/utf8"
)

func CodepageToUTF8(b []byte) ([]byte, error) {
	if !utf8.Valid(b) {
		reader := transform.NewReader(bytes.NewReader(b), simplifiedchinese.GBK.NewDecoder())
		d, e := ioutil.ReadAll(reader)
		if e != nil {
			return nil, e
		}
		return d, nil
	}
	return b, nil
}
