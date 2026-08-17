// Package httpapi is the broker's HTTP transport: one route, over mutual TLS.
//
// # Why HTTP and not gRPC
//
// The service has exactly one operation — hand over a CSR, get a certificate
// back — with no streaming and no bidirectional anything, so gRPC's advantages
// do not apply. What it would cost is real: a protobuf and gRPC dependency
// tree in a process whose entire job is minting credentials that authenticate
// as Active Directory accounts. The module has no dependencies today, and for
// this service the auditability of that is a security property rather than
// minimalism for its own sake.
//
// The authentication is identical either way. gRPC transport credentials wrap
// the same crypto/tls handshake this package uses, and the SPIFFE ID comes out
// of the same verified peer certificate. Nothing about the security model is
// being traded away.
//
// The decision is also cheap to revisit. Everything above the wire lives in
// internal/broker, which knows nothing about HTTP; a gRPC transport would be a
// second thin adapter next to this one, not a rewrite.
//
// # Shape
//
//	POST /issue    {"csr": "<PEM>"}  ->  {"certificate": "<PEM>", "chain": [...], "backend": "..."}
//
// Every refusal is {"error": {"reason": ..., "message": ...}} with reason
// drawn from the broker's taxonomy, so a client branches on a stable token
// rather than parsing prose.
package httpapi

import (
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"mime"
	"net/http"

	"github.com/scootscootscootscoot/spiffe-ad-broker/internal/broker"
)

const (
	// IssuePath is the only route the broker serves. Anything else is a 404;
	// there is no health endpoint, no metrics endpoint, and no debug surface,
	// because every byte of surface here sits behind a credential-minting
	// service.
	IssuePath = "/issue"

	// maxRequestBytes bounds the request body. A PEM-armoured PKCS#10 request
	// for an RSA-4096 key is comfortably under 4 KiB; 64 KiB leaves room to
	// spare while making an unbounded read impossible.
	maxRequestBytes = 64 << 10
)

// Server adapts HTTP requests to the broker's authenticate-and-map path.
type Server struct {
	broker *broker.Broker
	log    *slog.Logger
}

// NewServer returns a Server. broker is required.
func NewServer(b *broker.Broker, log *slog.Logger) (*Server, error) {
	if b == nil {
		return nil, errors.New("httpapi: no broker")
	}
	if log == nil {
		log = slog.Default()
	}
	return &Server{broker: b, log: log}, nil
}

// Handler returns the route table.
//
// The two patterns for IssuePath are both needed: the method-qualified one is
// the more specific match and takes POST, and the bare one catches every other
// method so it gets a 405 with an Allow header instead of falling through to
// the catch-all 404.
func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("POST "+IssuePath, s.handleIssue)
	mux.HandleFunc(IssuePath, s.methodNotAllowed)
	mux.HandleFunc("/", s.notFound)
	return mux
}

func (s *Server) handleIssue(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	// Authentication, before anything reads a single byte of the body.
	callerID, err := SPIFFEIDFromPeer(r.TLS)
	if err != nil {
		// The only refusal this package logs itself: it happens before the
		// broker is involved, so nothing else would record it.
		s.log.WarnContext(ctx, "refused an unauthenticated request",
			slog.String("detail", err.Error()),
			slog.String("remote", r.RemoteAddr))
		writeError(w, s.log, http.StatusUnauthorized, broker.ReasonUnauthenticated,
			"client certificate did not yield a verified SPIFFE ID")
		return
	}

	if err := requireJSON(r); err != nil {
		writeError(w, s.log, http.StatusUnsupportedMediaType, broker.ReasonInvalidRequest, err.Error())
		return
	}

	body, err := decodeBody(w, r)
	if err != nil {
		var maxErr *http.MaxBytesError
		if errors.As(err, &maxErr) {
			writeError(w, s.log, http.StatusRequestEntityTooLarge, broker.ReasonInvalidRequest,
				fmt.Sprintf("request body exceeds %d bytes", maxRequestBytes))
			return
		}
		writeError(w, s.log, http.StatusBadRequest, broker.ReasonInvalidRequest, err.Error())
		return
	}

	csrDER, err := decodeCSRPEM(body.CSR)
	if err != nil {
		writeError(w, s.log, http.StatusBadRequest, broker.ReasonInvalidRequest, err.Error())
		return
	}

	cred, err := s.broker.Issue(ctx, callerID, csrDER)
	if err != nil {
		// Already logged, with the caller and snapshot version attached, at
		// the point the decision was made. Translate, do not re-report.
		var bErr *broker.Error
		if errors.As(err, &bErr) {
			writeError(w, s.log, statusFor(bErr.Reason), bErr.Reason, bErr.Message)
			return
		}
		s.log.ErrorContext(ctx, "broker returned an unclassified error",
			slog.String("detail", err.Error()))
		writeError(w, s.log, http.StatusInternalServerError, broker.ReasonInternal, "issuance failed")
		return
	}

	resp := issueResponse{
		Certificate: encodeCertPEM(cred.Certificate),
		Chain:       make([]string, 0, len(cred.Chain)),
		Backend:     s.broker.BackendName(),
	}
	for _, c := range cred.Chain {
		resp.Chain = append(resp.Chain, encodeCertPEM(c))
	}
	writeJSON(w, s.log, http.StatusOK, resp)
}

func (s *Server) methodNotAllowed(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Allow", http.MethodPost)
	writeError(w, s.log, http.StatusMethodNotAllowed, broker.ReasonInvalidRequest,
		fmt.Sprintf("%s is not allowed on %s", r.Method, IssuePath))
}

func (s *Server) notFound(w http.ResponseWriter, _ *http.Request) {
	writeError(w, s.log, http.StatusNotFound, broker.ReasonInvalidRequest, "no such route")
}

// requireJSON rejects a body whose declared type is not JSON. Parameters such
// as "; charset=utf-8" are tolerated; a missing or different media type is not.
func requireJSON(r *http.Request) error {
	ct := r.Header.Get("Content-Type")
	if ct == "" {
		return errors.New("Content-Type is required and must be application/json")
	}
	mediaType, _, err := mime.ParseMediaType(ct)
	if err != nil {
		return fmt.Errorf("Content-Type %q is malformed", ct)
	}
	if mediaType != "application/json" {
		return fmt.Errorf("Content-Type %q is not application/json", mediaType)
	}
	return nil
}

// decodeBody reads and strictly decodes the request body.
//
// Unknown fields are rejected, matching the mapping snapshot loader's stance
// and for the same reason: a client sending a field this build does not
// understand is a client that believes something is being honoured. Trailing
// content is rejected so a body cannot carry a second document nobody reads.
func decodeBody(w http.ResponseWriter, r *http.Request) (issueRequest, error) {
	r.Body = http.MaxBytesReader(w, r.Body, maxRequestBytes)

	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()

	var body issueRequest
	if err := dec.Decode(&body); err != nil {
		return issueRequest{}, err
	}
	if dec.More() {
		return issueRequest{}, errors.New("unexpected trailing content after the request object")
	}
	return body, nil
}

// statusFor maps a refusal reason to an HTTP status.
//
// no_mapping is 403 rather than 404: the caller authenticated successfully and
// was denied, which is what 403 means. 404 would frame an authorization
// decision as a missing resource and invite a client to retry it as though the
// mapping might appear.
func statusFor(reason broker.Reason) int {
	switch reason {
	case broker.ReasonUnauthenticated:
		return http.StatusUnauthorized
	case broker.ReasonInvalidRequest:
		return http.StatusBadRequest
	case broker.ReasonNoMapping:
		return http.StatusForbidden
	case broker.ReasonNotImplemented:
		return http.StatusNotImplemented
	default:
		return http.StatusInternalServerError
	}
}

func writeError(w http.ResponseWriter, log *slog.Logger, status int, reason broker.Reason, message string) {
	writeJSON(w, log, status, errorResponse{Error: errorBody{
		Reason:  string(reason),
		Message: message,
	}})
}

func writeJSON(w http.ResponseWriter, log *slog.Logger, status int, payload any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	if err := json.NewEncoder(w).Encode(payload); err != nil {
		// The status line is already on the wire, so there is nothing to say
		// to the client. Record it and move on.
		log.Error("failed to write response body", slog.String("detail", err.Error()))
	}
}
