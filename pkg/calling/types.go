package calling

// TurnToken describes a TURN server credential set matching the Java Signal
// Server's TurnToken record.
type TurnToken struct {
	Username    string   `json:"username"`
	Password    string   `json:"password"`
	TTLSeconds  int64    `json:"ttl"`
	URLs        []string `json:"urls"`
	URLsWithIPs []string `json:"urlsWithIps"`
	Hostname    string   `json:"hostname,omitempty"`
}

// GetCallingRelaysResponse contains the TURN relay servers for call setup.
type GetCallingRelaysResponse struct {
	Relays []TurnToken `json:"relays"`
}

// CreateCallLinkCredentialRequest is the client's request to create a call
// link credential. The request bytes are the serialized zkgroup request.
type CreateCallLinkCredentialRequest struct {
	CreateCallLinkCredentialRequest []byte `json:"createCallLinkCredentialRequest"`
}

// CreateCallLinkCredentialResponse is the server's response containing the
// issued credential and its redemption time.
type CreateCallLinkCredentialResponse struct {
	Credential     []byte `json:"credential"`
	RedemptionTime int64  `json:"redemptionTime"`
}

// CallQualitySurveyRequest is the raw request body for a call quality survey
// submission. Fields match the Java SubmitCallQualitySurveyRequest protobuf.
type CallQualitySurveyRequest struct {
	UserSatisfied   bool     `json:"userSatisfied"`
	StartTimestamp  int64    `json:"startTimestamp"`
	EndTimestamp    int64    `json:"endTimestamp"`
	CallType        string   `json:"callType"`
	Success         bool     `json:"success"`
	CallEndReason   string   `json:"callEndReason"`
	QualityIssues   []string `json:"callQualityIssues,omitempty"`
	AdditionalNotes string   `json:"additionalIssuesDescription,omitempty"`
	DebugLogURL     string   `json:"debugLogUrl,omitempty"`
}

// CallQualitySurveyMessage is the internal representation of a call quality
// survey, enriched with server-side metadata before publishing.
type CallQualitySurveyMessage struct {
	ResponseID      string   `json:"responseId"`
	SubmissionTime  int64    `json:"submissionTimestamp"`
	UserSatisfied   bool     `json:"userSatisfied"`
	StartTimestamp  int64    `json:"startTimestamp"`
	EndTimestamp    int64    `json:"endTimestamp"`
	CallType        string   `json:"callType"`
	Success         bool     `json:"success"`
	CallEndReason   string   `json:"callEndReason"`
	QualityIssues   []string `json:"callQualityIssues,omitempty"`
	AdditionalNotes string   `json:"additionalIssuesDescription,omitempty"`
	DebugLogURL     string   `json:"debugLogUrl,omitempty"`
	ClientPlatform  string   `json:"clientPlatform,omitempty"`
	ClientVersion   string   `json:"clientVersion,omitempty"`
	RemoteAddr      string   `json:"remoteAddr,omitempty"`
}
