package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"regexp"
	"strings"
	"time"

	"imgsign/pkg/verifier"
)

const verificationTimeout = 8 * time.Second

var imageDigestPattern = regexp.MustCompile(`@sha256:[a-f0-9]{64}$`)

type admissionReview struct {
	APIVersion string             `json:"apiVersion"`
	Kind       string             `json:"kind"`
	Request    *admissionRequest  `json:"request"`
	Response   *admissionResponse `json:"response,omitempty"`
}

type admissionRequest struct {
	UID       string          `json:"uid"`
	Namespace string          `json:"namespace"`
	Resource  groupVersionRes `json:"resource"`
	Object    json.RawMessage `json:"object"`
}

type groupVersionRes struct {
	Resource string `json:"resource"`
}

type admissionResponse struct {
	UID     string  `json:"uid,omitempty"`
	Allowed bool    `json:"allowed"`
	Status  *status `json:"status,omitempty"`
}

type status struct {
	Code    int32  `json:"code,omitempty"`
	Reason  string `json:"reason,omitempty"`
	Message string `json:"message,omitempty"`
}

type pod struct {
	Kind     string      `json:"kind"`
	Metadata podMetadata `json:"metadata"`
	Spec     podSpec     `json:"spec"`
}

type podMetadata struct {
	Name      string `json:"name"`
	Namespace string `json:"namespace"`
}

type podSpec struct {
	Containers          []container `json:"containers"`
	InitContainers      []container `json:"initContainers"`
	EphemeralContainers []container `json:"ephemeralContainers"`
}

type container struct {
	Image string `json:"image"`
}

type verifyImage func(context.Context, string) error

type verifierHandler struct {
	verify verifyImage
	logger *log.Logger
}

type decisionLog struct {
	Time       string `json:"time"`
	Namespace  string `json:"namespace"`
	Pod        string `json:"pod"`
	Image      string `json:"image"`
	Decision   string `json:"decision"`
	Reason     string `json:"reason"`
	DurationMS int64  `json:"duration_ms"`
}

type imageDecision struct {
	image    string
	decision string
	reason   string
}

func (h *verifierHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	requestStart := time.Now()
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var review admissionReview
	if err := json.NewDecoder(io.LimitReader(r.Body, 1<<20)).Decode(&review); err != nil {
		h.logDecision("", "", "", "deny", "malformed_review", time.Since(requestStart))
		h.writeResponse(w, "", false, "malformed_review", "invalid AdmissionReview JSON")
		return
	}
	if review.APIVersion != "admission.k8s.io/v1" || review.Kind != "AdmissionReview" {
		h.logDecision("", "", "", "deny", "malformed_review", time.Since(requestStart))
		h.writeResponse(w, "", false, "malformed_review", "AdmissionReview v1 is required")
		return
	}
	if review.Request == nil {
		h.logDecision("", "", "", "deny", "malformed_review", time.Since(requestStart))
		h.writeResponse(w, "", false, "malformed_review", "AdmissionReview request is required")
		return
	}
	if review.Request.Object == nil {
		h.logDecision(review.Request.Namespace, "", "", "deny", "malformed_review", time.Since(requestStart))
		h.writeResponse(w, review.Request.UID, false, "malformed_review", "AdmissionReview object is required")
		return
	}

	var p pod
	if err := json.Unmarshal(review.Request.Object, &p); err != nil || p.Kind != "Pod" {
		h.logDecision(review.Request.Namespace, "", "", "deny", "malformed_review", time.Since(requestStart))
		h.writeResponse(w, review.Request.UID, false, "malformed_review", "AdmissionReview object must be a Pod")
		return
	}

	namespace := review.Request.Namespace
	if namespace == "" {
		namespace = p.Metadata.Namespace
	}
	images := podImages(p)
	decisions := make([]imageDecision, 0, len(images))
	var rejectedImage, rejectionReason string
	for _, image := range images {
		reason := "valid"
		decision := "allow"
		if !imageDigestPattern.MatchString(image) {
			reason = "tag_not_allowed"
			decision = "deny"
		} else {
			ctx, cancel := context.WithTimeout(r.Context(), verificationTimeout)
			err := h.verify(ctx, image)
			cancel()
			if err != nil {
				reason = verifierReason(err)
				decision = "deny"
			}
		}
		if decision == "deny" {
			rejectedImage, rejectionReason = image, reason
		}
		decisions = append(decisions, imageDecision{image: image, decision: decision, reason: reason})
		if decision == "deny" {
			break
		}
	}

	if len(decisions) == 0 {
		decisions = append(decisions, imageDecision{decision: "allow", reason: "valid"})
	}
	requestDuration := time.Since(requestStart)
	for _, result := range decisions {
		h.logDecision(namespace, p.Metadata.Name, result.image, result.decision, result.reason, requestDuration)
	}

	if rejectionReason != "" {
		h.writeResponse(w, review.Request.UID, false, rejectionReason,
			fmt.Sprintf("image %q rejected: %s", rejectedImage, rejectionReason))
		return
	}

	h.writeResponse(w, review.Request.UID, true, "valid", "all Pod images are valid")
}

func podImages(p pod) []string {
	images := make([]string, 0, len(p.Spec.Containers)+len(p.Spec.InitContainers)+len(p.Spec.EphemeralContainers))
	for _, group := range [][]container{p.Spec.Containers, p.Spec.InitContainers, p.Spec.EphemeralContainers} {
		for _, c := range group {
			images = append(images, c.Image)
		}
	}
	return images
}

func verifierReason(err error) string {
	code := verifier.Code(err)
	if strings.HasPrefix(code, "error: ") {
		return "verify_error"
	}
	return code
}

func (h *verifierHandler) logDecision(namespace, podName, image, decision, reason string, duration time.Duration) {
	entry := decisionLog{
		Time:       time.Now().UTC().Format(time.RFC3339Nano),
		Namespace:  namespace,
		Pod:        podName,
		Image:      image,
		Decision:   decision,
		Reason:     reason,
		DurationMS: duration.Milliseconds(),
	}
	data, err := json.Marshal(entry)
	if err == nil {
		h.logger.Print(string(data))
	}
}

func (h *verifierHandler) writeResponse(w http.ResponseWriter, uid string, allowed bool, reason, message string) {
	response := admissionReview{
		APIVersion: "admission.k8s.io/v1",
		Kind:       "AdmissionReview",
		Response: &admissionResponse{
			UID:     uid,
			Allowed: allowed,
			Status:  &status{Reason: reason, Message: message},
		},
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(response)
}
