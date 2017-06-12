package saml

import (
	"net/http"
	"net/http/httptest"
	"regexp"
	"testing"
	"time"

	"github.com/murphybytes/saml/generated"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestGetUniqueID(t *testing.T) {
	hashtbl := map[string]int{}
	for i := 0; i < 100; i++ {
		newID, err := getUniqueID()
		require.Nil(t, err)
		// check for duplicates
		_, ok := hashtbl[newID]
		require.False(t, ok)
		hashtbl[newID] = 0

		for _, b := range newID {
			require.True(t, (b >= 65 && b <= 90) || (b >= 97 && b <= 122) || (b >= 48 && b <= 57))
		}
	}
}

func TestGetMetadataURL(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		buff, err := generated.Asset("test_data/metadata.xml")
		require.Nil(t, err)
		time.Sleep(1 * time.Second)
		w.Write(buff)
	}))
	defer ts.Close()
	ed, err := GetMetadataFromURL(ts.URL)
	require.Nil(t, err)
	assert.NotNil(t, ed)

}

func TestGetMetadataURLTimeout(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		buff, err := generated.Asset("test_data/metadata.xml")
		require.Nil(t, err)
		time.Sleep(200 * time.Millisecond)
		w.Write(buff)
	}))
	defer ts.Close()
	_, err := GetMetadataFromURL(ts.URL, WithTimeout(100*time.Millisecond))
	require.NotNil(t, err)
	assert.Regexp(t, regexp.MustCompile(`^getting metadata`), err.Error())
}
