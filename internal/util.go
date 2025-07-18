package internal

import (
	"errors"
	"strings"
)

func StringAddressed(str string) *string {
	return &str
}

func MergeMaps(maps ...map[string]string) map[string]string {
	result := make(map[string]string)
	for _, imap := range maps {
		for k, v := range imap {
			result[k] = v
		}
	}
	return result
}

func ParseAzureResourceID(resourceID string) (map[string]string, error) {
	if resourceID == "" {
		return nil, errors.New("resourceID cannot be empty")
	}

	parts := strings.Split(strings.Trim(resourceID, "/"), "/")
	if len(parts)%2 != 0 {
		return nil, errors.New("invalid Azure resource ID format")
	}

	result := make(map[string]string)
	for i := 0; i < len(parts)-1; i += 2 {
		result[parts[i]] = parts[i+1]
	}
	return result, nil
}

// normaliseLocation converts a location string to a lower case and all spaces removed.
// This is useful for ensuring consistent formatting of location strings between different services that report on a different format.
// For example, "UK South" and "uksouth" should be treated the same.
func normaliseLocation(location string) string {
	return strings.ToLower(strings.ReplaceAll(location, " ", ""))
}
