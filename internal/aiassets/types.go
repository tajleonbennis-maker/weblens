package aiassets

import (
	"github.com/tajleonbennis-maker/weblens/internal/keydetect"
	"time"
)

type Evidence struct {
	Source string `json:"source"`
	Detail string `json:"detail"`
}
type Technology struct {
	Name       string     `json:"name"`
	Category   string     `json:"category"`
	Confidence int        `json:"confidence"`
	Evidence   []Evidence `json:"evidence"`
}
type Model struct {
	Provider   string     `json:"provider"`
	Model      string     `json:"model,omitempty"`
	Confidence int        `json:"confidence"`
	Status     string     `json:"status"`
	Evidence   []Evidence `json:"evidence"`
}
type Exposure struct {
	Provider    string `json:"provider,omitempty"`
	Kind        string `json:"kind"`
	MaskedKey   string `json:"maskedKey"`
	Fingerprint string `json:"fingerprint"`
	Confidence  string `json:"confidence"`
	Location    string `json:"location"`
	Offset      int    `json:"offset"`
	Context     string `json:"context,omitempty"`
}
type Asset struct {
	AssetURL     string       `json:"assetUrl"`
	FinalURL     string       `json:"finalUrl,omitempty"`
	Origin       string       `json:"origin,omitempty"`
	DiscoveredBy string       `json:"discoveredBy"`
	HTTPStatus   int          `json:"httpStatus,omitempty"`
	Title        string       `json:"title,omitempty"`
	Reachable    bool         `json:"reachable"`
	AIChat       bool         `json:"aiChat"`
	Blocked      bool         `json:"blocked,omitempty"`
	Error        string       `json:"error,omitempty"`
	Technologies []Technology `json:"technologies,omitempty"`
	Models       []Model      `json:"models,omitempty"`
	KeyExposures []Exposure   `json:"keyExposures,omitempty"`
	ResourceURLs []string     `json:"resourceUrls,omitempty"`
	StaticBytes  int64        `json:"staticBytes,omitempty"`
	DynamicBytes int64        `json:"dynamicBytes,omitempty"`
	CollectedAt  time.Time    `json:"collectedAt"`
}
type Candidate struct {
	URL          string `json:"url"`
	DiscoveredBy string `json:"discoveredBy"`
}
type Summary struct {
	StartedAt       time.Time      `json:"startedAt"`
	FinishedAt      time.Time      `json:"finishedAt"`
	Candidates      int            `json:"candidates"`
	Scanned         int            `json:"scanned"`
	AIChatAssets    int            `json:"aiChatAssets"`
	ExposureAssets  int            `json:"exposureAssets"`
	WrittenBytes    int64          `json:"writtenBytes"`
	LimitBytes      int64          `json:"limitBytes"`
	StopReason      string         `json:"stopReason"`
	TechnologyCount map[string]int `json:"technologyCount,omitempty"`
	ModelCount      map[string]int `json:"modelCount,omitempty"`
}

func exposureFromFinding(f keydetect.Finding, location string) Exposure {
	return Exposure{Provider: f.Provider, Kind: f.Kind, MaskedKey: f.MaskedKey, Fingerprint: f.Fingerprint, Confidence: f.Confidence, Location: location, Offset: f.Offset, Context: f.Context}
}
