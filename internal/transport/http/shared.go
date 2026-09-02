package http

import (
	"crypto/rand"
	"encoding/hex"
	"mime"
	stdhttp "net/http"
	"reflect"
	"strings"

	"github.com/phall1/blackbird/internal/domain"
)

const (
	mediaTypeJSON    = "application/json"
	mediaTypeProblem = "application/problem+json"
	headerRequestID  = "X-Request-ID"
)

func inboundRequestID(request *stdhttp.Request) string {
	values := request.Header.Values(headerRequestID)
	if len(values) == 1 && (strings.HasPrefix(values[0], "req-") || strings.HasPrefix(values[0], "req_")) && len(values[0]) <= 128 && !strings.ContainsAny(values[0], " \t\r\n") {
		return values[0]
	}
	return newRequestID()
}

func isJSONContentType(value string) bool {
	mediaType, parameters, err := mime.ParseMediaType(value)
	return err == nil && mediaType == mediaTypeJSON && len(parameters) == 0
}

func statusFor(code domain.ErrorCode) int {
	switch code {
	case domain.ErrorCodeInvalidArgument, domain.ErrorCodeCursorInvalid, domain.ErrorCodeCursorScopeMismatch:
		return stdhttp.StatusBadRequest
	case domain.ErrorCodeUnauthenticated:
		return stdhttp.StatusUnauthorized
	case domain.ErrorCodeNotFound:
		return stdhttp.StatusNotFound
	case domain.ErrorCodeLeaseConflict, domain.ErrorCodeLeaseExpired, domain.ErrorCodeFenceRejected:
		return stdhttp.StatusConflict
	case domain.ErrorCodeCursorExpired:
		return stdhttp.StatusGone
	case domain.ErrorCodeBackpressure:
		return stdhttp.StatusServiceUnavailable
	default:
		return stdhttp.StatusInternalServerError
	}
}

func newRequestID() string {
	var random [16]byte
	if _, err := rand.Read(random[:]); err != nil {
		return "req_transport_internal"
	}
	return "req_" + hex.EncodeToString(random[:])
}

func isNil(value any) bool {
	if value == nil {
		return true
	}
	reflected := reflect.ValueOf(value)
	switch reflected.Kind() {
	case reflect.Chan, reflect.Func, reflect.Interface, reflect.Map, reflect.Pointer, reflect.Slice:
		return reflected.IsNil()
	default:
		return false
	}
}
