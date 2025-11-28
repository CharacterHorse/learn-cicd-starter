package auth_test

import (
	"errors"
	"net/http"
	"testing"

	"github.com/bootdotdev/learn-cicd-starter/internal/auth"
)

func TestGetAPIKey(t *testing.T) {
	tests := []struct {
		name string // description of this test case
		// Named input parameters for target function.
		headers http.Header
		want    string
		wantErr bool
		err     error
	}{
		{
			name:    "No Authorization header",
			headers: http.Header{},
			want:    "",
			wantErr: true,
			err:     auth.ErrNoAuthHeaderIncluded,
		},
		{
			name: "Malformed Authorization header - less than 2 parts",
			headers: http.Header{
				"Authorization": []string{"ApiKey"},
			},
			want:    "",
			wantErr: true,
			err:     errors.New("malformed authorization header"),
		},
		{
			name: "Malformed Authorization header - wrong scheme",
			headers: http.Header{
				"Authorization": []string{"Bearer somekey"},
			},
			want:    "",
			wantErr: true,
			err:     errors.New("malformed authorization header"),
		},
		{
			name: "Valid Authorization header",
			headers: http.Header{
				"Authorization": []string{"ApiKey 12345"},
			},
			want:    "12345",
			wantErr: false,
			err:     nil,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, gotErr := auth.GetAPIKey(tt.headers)
			if (gotErr != nil) != tt.wantErr {
				t.Errorf("GetAPIKey() error = %v, wantErr %v", gotErr, tt.wantErr)
				return
			}
			if tt.wantErr {
				if gotErr.Error() != tt.err.Error() {
					t.Errorf("GetAPIKey() error = %v, want %v", gotErr, tt.err)
				}
				return
			}
			if got != tt.want {
				t.Errorf("GetAPIKey() = %v, want %v", got, tt.want)
			}
		})
	}
}
