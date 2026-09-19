package jitsi

// ai-generated: the whole file (the bridge's own sources, which the remote
// video latch must never take for the peer's).

import (
	"encoding/json"
	"encoding/xml"
	"strconv"
)

// bridgeOwner is the owner Jicofo files the bridge's own sources under: the
// owner attribute of an XML source's <ssrc-info>, and the key of the JSON
// source map.
const bridgeOwner = "jvb"

// initiateSources is what a session-initiate says about sources: the
// <source> elements of each content, or the JSON map Jicofo sends in their
// place to an endpoint that reads it.
type initiateSources struct {
	Jingle struct {
		JSON     string `xml:"json-message"` //nolint:tagliatelle // Jingle element name
		Contents []struct {
			Sources []struct {
				SSRC  string `xml:"ssrc,attr"`
				Owner struct {
					Name string `xml:"owner,attr"`
				} `xml:"ssrc-info"` //nolint:tagliatelle // Jingle element name
			} `xml:"description>source"`
		} `xml:"content"`
	} `xml:"jingle"`
}

// bridgeSSRCs returns the SSRCs a session-initiate announces as the bridge's
// own. JVB probes an endpoint's bandwidth with padding on its own video
// source, under whichever video payload type it picks, and a probe can reach
// the endpoint before the peer's first packet does.
func bridgeSSRCs(stanza string) map[uint32]bool {
	var initiate initiateSources
	if err := xml.Unmarshal([]byte(stanza), &initiate); err != nil {
		return nil
	}
	own := make(map[uint32]bool)
	for _, content := range initiate.Jingle.Contents {
		for _, source := range content.Sources {
			ssrc, err := strconv.ParseUint(source.SSRC, 10, 32)
			if err == nil && ssrc != 0 && source.Owner.Name == bridgeOwner {
				own[uint32(ssrc)] = true
			}
		}
	}
	addJSONBridgeSSRCs(own, initiate.Jingle.JSON)
	return own
}

// addJSONBridgeSSRCs adds the bridge's SSRCs from Jicofo's JSON source map:
// per owner, lists of sources ({"s": ssrc, ...}) and of SSRC groups.
func addJSONBridgeSSRCs(own map[uint32]bool, raw string) {
	var message struct {
		Sources map[string][]json.RawMessage `json:"sources"`
	}
	if raw == "" || json.Unmarshal([]byte(raw), &message) != nil {
		return
	}
	for _, list := range message.Sources[bridgeOwner] {
		var sources []struct {
			SSRC uint32 `json:"s"`
		}
		if json.Unmarshal(list, &sources) != nil {
			continue // a list of SSRC groups
		}
		for _, source := range sources {
			if source.SSRC != 0 {
				own[source.SSRC] = true
			}
		}
	}
}

// noteBridgeSources records the bridge's own SSRCs from the session-initiate
// a PeerConnection is about to answer, before any RTP can arrive on it.
func (s *Session) noteBridgeSources(stanza string) {
	own := bridgeSSRCs(stanza)
	s.bridgeSSRCs.Store(&own)
}

// isBridgeSSRC reports whether ssrc is one the bridge sends on its own
// behalf rather than one it forwards from a participant.
func (s *Session) isBridgeSSRC(ssrc uint32) bool {
	own := s.bridgeSSRCs.Load()
	return own != nil && (*own)[ssrc]
}
