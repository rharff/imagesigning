package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"log"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"imgsign/pkg/verifier"
)

func TestHandlerAllowsValidImages(t *testing.T) {
	h, _ := testHandler(func(_ context.Context, image string) error {
		if image != "ghcr.io/acme/app@sha256:"+strings.Repeat("a", 64) {
			t.Fatalf("unexpected image: %s", image)
		}
		return nil
	})
	response := callHandler(t, h, podReview(t, "uid-1", `{"kind":"Pod","metadata":{"name":"api","namespace":"prod"},"spec":{"containers":[{"image":"ghcr.io/acme/app@sha256:`+strings.Repeat("a", 64)+`"}]}}`))
	if response.Response.Allowed != true {
		t.Fatalf("expected allow: %+v", response.Response)
	}
}

func TestHandlerLogsWholeAdmissionReviewDuration(t *testing.T) {
	delay := 20 * time.Millisecond
	h, logs := testHandler(func(context.Context, string) error {
		time.Sleep(delay)
		return nil
	})
	image := "ghcr.io/acme/app@sha256:" + strings.Repeat("a", 64)
	object := `{"kind":"Pod","metadata":{"name":"api"},"spec":{"containers":[{"image":"` +
		image + `"},{"image":"` + image + `"}]}}`
	response := callHandler(t, h, podReview(t, "uid-duration", object))
	if !response.Response.Allowed {
		t.Fatalf("expected allow: %+v", response.Response)
	}

	lines := strings.Split(strings.TrimSpace(logs.String()), "\n")
	if len(lines) != 2 {
		t.Fatalf("got %d decision logs, want 2: %s", len(lines), logs.String())
	}
	var first, second decisionLog
	if err := json.Unmarshal([]byte(lines[0]), &first); err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal([]byte(lines[1]), &second); err != nil {
		t.Fatal(err)
	}
	minimumDurationMS := (2 * delay).Milliseconds()
	if first.DurationMS < minimumDurationMS || second.DurationMS < minimumDurationMS {
		t.Fatalf("durations do not include both verifications: first=%d ms, second=%d ms", first.DurationMS, second.DurationMS)
	}
	if first.DurationMS != second.DurationMS {
		t.Fatalf("decision logs should report the same AdmissionReview duration: first=%d ms, second=%d ms", first.DurationMS, second.DurationMS)
	}
}

func TestHandlerDeniesVerifierReasonAndIncludesImage(t *testing.T) {
	image := "ghcr.io/acme/app@sha256:" + strings.Repeat("b", 64)
	h, _ := testHandler(func(context.Context, string) error {
		return &verifier.Rejection{Code: verifier.BadSignature}
	})
	response := callHandler(t, h, podReview(t, "uid-2", podJSON(image)))
	if response.Response.Allowed || response.Response.Status.Reason != verifier.BadSignature ||
		!strings.Contains(response.Response.Status.Message, image) {
		t.Fatalf("unexpected response: %+v", response.Response)
	}
}

func TestHandlerRejectsTag(t *testing.T) {
	h, _ := testHandler(func(context.Context, string) error {
		t.Fatal("verifier must not run for a tag")
		return nil
	})
	response := callHandler(t, h, podReview(t, "uid-3", podJSON("ghcr.io/acme/app:latest")))
	if response.Response.Allowed || response.Response.Status.Reason != "tag_not_allowed" {
		t.Fatalf("unexpected response: %+v", response.Response)
	}
}

func TestHandlerRejectsInvalidInitContainer(t *testing.T) {
	valid := "ghcr.io/acme/app@sha256:" + strings.Repeat("c", 64)
	invalid := "ghcr.io/acme/init:latest"
	h, _ := testHandler(func(_ context.Context, image string) error {
		if image == invalid {
			t.Fatal("tagged init container must be rejected before verification")
		}
		return nil
	})
	object := `{"kind":"Pod","metadata":{"name":"worker"},"spec":{"containers":[{"image":"` + valid + `"}],"initContainers":[{"image":"` + invalid + `"}]}}`
	response := callHandler(t, h, podReview(t, "uid-4", object))
	if response.Response.Allowed || response.Response.Status.Reason != "tag_not_allowed" ||
		!strings.Contains(response.Response.Status.Message, invalid) {
		t.Fatalf("unexpected response: %+v", response.Response)
	}
}

func TestHandlerRejectsOperationalError(t *testing.T) {
	h, _ := testHandler(func(context.Context, string) error {
		return errors.New("registry unavailable")
	})
	response := callHandler(t, h, podReview(t, "uid-5", podJSON("ghcr.io/acme/app@sha256:"+strings.Repeat("d", 64))))
	if response.Response.Allowed || response.Response.Status.Reason != "verify_error" {
		t.Fatalf("unexpected response: %+v", response.Response)
	}
}

func TestHandlerRejectsMalformedAdmissionReview(t *testing.T) {
	h, _ := testHandler(nil)
	req := httptest.NewRequest(http.MethodPost, "/validate", strings.NewReader("{"))
	recorder := httptest.NewRecorder()
	h.ServeHTTP(recorder, req)
	var response admissionReview
	if err := json.Unmarshal(recorder.Body.Bytes(), &response); err != nil {
		t.Fatal(err)
	}
	if response.Response == nil || response.Response.Allowed || response.Response.Status.Reason != "malformed_review" {
		t.Fatalf("unexpected response: %+v", response.Response)
	}
}

func testHandler(verify verifyImage) (*verifierHandler, *bytes.Buffer) {
	var logs bytes.Buffer
	return &verifierHandler{verify: verify, logger: log.New(&logs, "", 0)}, &logs
}

func callHandler(t *testing.T, h *verifierHandler, body string) admissionReview {
	t.Helper()
	req := httptest.NewRequest(http.MethodPost, "/validate", strings.NewReader(body))
	recorder := httptest.NewRecorder()
	h.ServeHTTP(recorder, req)
	var response admissionReview
	if err := json.Unmarshal(recorder.Body.Bytes(), &response); err != nil {
		t.Fatal(err)
	}
	return response
}

func podReview(t *testing.T, uid, object string) string {
	t.Helper()
	review := admissionReview{
		APIVersion: "admission.k8s.io/v1",
		Kind:       "AdmissionReview",
		Request: &admissionRequest{
			UID:    uid,
			Object: json.RawMessage(object),
		},
	}
	data, err := json.Marshal(review)
	if err != nil {
		t.Fatal(err)
	}
	return string(data)
}

func podJSON(image string) string {
	return `{"kind":"Pod","metadata":{"name":"api"},"spec":{"containers":[{"image":"` + image + `"}]}}`
}
