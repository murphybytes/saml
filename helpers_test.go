package saml

import (
	"testing"

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
