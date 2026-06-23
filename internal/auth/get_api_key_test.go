package auth

import (
	"errors"
	"net/http"
	"testing"
)

func TestGetAPIKey(t *testing.T) {
	tests := []struct {
		name    string
		headers http.Header
		want    string
		wantErr error
	}{
		{
			name:    "valid api key",
			headers: http.Header{"Authorization": []string{"ApiKey 12345"}},
			want:    "12345",
			wantErr: nil,
		},
		{
			name:    "no authorization header",
			headers: http.Header{},
			want:    "",
			wantErr: ErrNoAuthHeaderIncluded,
		},
		{
			name:    "empty authorization header",
			headers: http.Header{"Authorization": []string{""}},
			want:    "",
			wantErr: ErrNoAuthHeaderIncluded,
		},
		{
			name:    "malformed header - missing key",
			headers: http.Header{"Authorization": []string{"ApiKey"}},
			want:    "",
			wantErr: errors.New("malformed authorization header"),
		},
		{
			name:    "malformed header - wrong prefix",
			headers: http.Header{"Authorization": []string{"Bearer 12345"}},
			want:    "",
			wantErr: errors.New("malformed authorization header"),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := GetAPIKey(tt.headers)

			if got != tt.want {
				t.Errorf("GetAPIKey() = %q, want %q", got, tt.want)
			}

			if tt.wantErr == nil {
				if err != nil {
					t.Errorf("GetAPIKey() unexpected error = %v", err)
				}
				return
			}

			if err == nil {
				t.Fatalf("GetAPIKey() expected error %v, got nil", tt.wantErr)
			}
			if err.Error() != tt.wantErr.Error() {
				t.Errorf("GetAPIKey() error = %v, want %v", err, tt.wantErr)
			}
		})
	}
}
