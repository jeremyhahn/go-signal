package signal

import (
	"bytes"
	"context"
	"encoding/hex"
	"fmt"
	"io"
	"mime/multipart"
	"net/http"
	"strconv"
	"strings"

	signalerrors "github.com/jeremyhahn/go-signal/pkg/errors"

	"github.com/jeremyhahn/go-signal/pkg/stickers"
)

// ListStickerPacks returns every locally-installed sticker pack from
// the registry. Empty when no packs have been added yet.
func (c *Client) ListStickerPacks() ([]InstalledStickerPack, error) {
	return c.store.GetStickerPacks()
}

// SaveStickerPack persists a pack into the local registry. Idempotent
// upsert — the SDK identifies rows by PackID.
func (c *Client) SaveStickerPack(pack *InstalledStickerPack) error {
	return c.store.SaveStickerPack(pack)
}

// DeleteStickerPack removes the pack record by PackID. Idempotent —
// removing a missing pack is not an error.
func (c *Client) DeleteStickerPack(packID string) error {
	return c.store.DeleteStickerPack(packID)
}

// StickerPath formats the CDN object path for one sticker in a pack.
// id=-1 selects the manifest slot; id>=0 selects sticker index id.
// Mirrors the path layout pkg/stickers/manager.go writes when
// signing upload forms.
func StickerPath(packID string, id int) string {
	if id < 0 {
		return "/cdn3/stickers/" + packID + "/manifest.proto"
	}
	return "/cdn3/stickers/" + packID + "/full/" + strconv.Itoa(id)
}

// GetSticker downloads a single sticker payload from the configured
// signal server's embedded CDN, verifies the HMAC, decrypts it with
// packKey, and returns the plaintext bytes. Use id=-1 to retrieve
// the encoded Pack manifest instead.
//
// Production deployments that serve stickers from S3 must surface a
// signed-GET endpoint on the server side; this SDK method only
// targets the embedded-CDN path that ships with go-signal's REST
// server.
func (c *Client) GetSticker(ctx context.Context, packID string, id int, packKey []byte) ([]byte, error) {
	if packID == "" {
		return nil, signalerrors.New(signalerrors.ErrInvalidArgument, "signal: packID is required")
	}
	if len(packKey) != stickers.PackKeyLen {
		return nil, signalerrors.New(signalerrors.ErrInvalidArgument, "signal: pack key must be "+strconv.Itoa(stickers.PackKeyLen)+" bytes, got "+strconv.Itoa(len(packKey)))
	}
	endpoint := c.config.ServerURL + StickerPath(packID, id)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return nil, err
	}
	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode >= 400 {
		body, _ := io.ReadAll(resp.Body)
		return nil, &APIError{StatusCode: resp.StatusCode, Message: string(body)}
	}
	envelope, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, signalerrors.Wrap(signalerrors.ErrInternal, "read sticker body", err)
	}
	return stickers.DecryptPackPayload(packKey, envelope)
}

// StickerPackUpload is the outcome of a successful UploadStickerPack.
// The (PackID, PackKey) pair is the share URL the operator hands to
// other Signal users.
type StickerPackUpload struct {
	PackID  string
	PackKey []byte
	URL     string
}

// UploadStickerPack reads manifest.json + every referenced sticker
// image from path, encrypts everything with a fresh pack key, fetches
// a signed CDN upload form from the configured Signal server, and
// uploads each payload. Returns the share URL on success.
//
// path may be:
//   - a directory containing manifest.json
//   - a path ending in `manifest.json` (parent treated as the pack root)
//   - a .zip archive of the same layout
//
// The pack key MUST be persisted by the caller — Signal stores no
// copy of it server-side, so losing the key means the pack can never
// be decrypted again.
func (c *Client) UploadStickerPack(ctx context.Context, path string) (*StickerPackUpload, error) {
	pack, err := stickers.LoadPack(path)
	if err != nil {
		return nil, err
	}

	manifestProto := stickers.EncodePackManifest(pack)

	packKey, err := stickers.NewPackKey()
	if err != nil {
		return nil, signalerrors.Wrap(signalerrors.ErrInternal, "generate pack key", err)
	}

	encryptedManifest, err := stickers.EncryptPackPayload(packKey, manifestProto)
	if err != nil {
		return nil, signalerrors.Wrap(signalerrors.ErrInternal, "encrypt manifest", err)
	}
	encryptedStickers := make([][]byte, len(pack.Stickers))
	for i, s := range pack.Stickers {
		enc, err := stickers.EncryptPackPayload(packKey, s.Bytes)
		if err != nil {
			return nil, signalerrors.Wrap(signalerrors.ErrInternal, "encrypt sticker["+strconv.Itoa(i)+"]", err)
		}
		encryptedStickers[i] = enc
	}

	// Ask the Signal server for upload slots — one for the manifest,
	// plus one per sticker.
	form, err := c.getStickerUploadForm(ctx, len(pack.Stickers))
	if err != nil {
		return nil, signalerrors.Wrap(signalerrors.ErrInternal, "fetch upload form", err)
	}

	if err := c.uploadStickerPayload(ctx, form.Manifest, encryptedManifest); err != nil {
		return nil, signalerrors.Wrap(signalerrors.ErrInternal, "upload manifest", err)
	}
	if len(form.Stickers) != len(encryptedStickers) {
		return nil, signalerrors.New(signalerrors.ErrInternal, "server returned "+strconv.Itoa(len(form.Stickers))+" sticker slots, want "+strconv.Itoa(len(encryptedStickers)))
	}
	for i, slot := range form.Stickers {
		if err := c.uploadStickerPayload(ctx, slot, encryptedStickers[i]); err != nil {
			return nil, signalerrors.Wrap(signalerrors.ErrInternal, "upload sticker["+strconv.Itoa(i)+"]", err)
		}
	}

	share := fmt.Sprintf("https://signal.art/addstickers/#pack_id=%s&pack_key=%s",
		form.PackId, hex.EncodeToString(packKey))
	return &StickerPackUpload{
		PackID:  form.PackId,
		PackKey: packKey,
		URL:     share,
	}, nil
}

// getStickerUploadForm calls GET /v1/sticker/pack/form/{count} on the
// signal server and decodes the response into a typed form.
func (c *Client) getStickerUploadForm(ctx context.Context, count int) (*stickers.StickerPackFormUpload, error) {
	var form stickers.StickerPackFormUpload
	if err := c.doRequest(ctx, http.MethodGet, "/v1/sticker/pack/form/"+strconv.Itoa(count), nil, &form); err != nil {
		return nil, err
	}
	return &form, nil
}

// uploadStickerPayload POSTs payload to the location identified by the
// supplied form field. Two paths:
//
//   - When the server returned a real S3 POST policy (Algorithm /
//     Policy / Signature populated), submit a multipart/form-data
//     request with each policy field plus the payload as the `file`
//     part. This is the wire shape S3 requires.
//
//   - Otherwise, fall back to the embedded-CDN path: a raw PUT to the
//     Location URL. Dev / single-node deployments use this branch.
func (c *Client) uploadStickerPayload(ctx context.Context, field stickers.StickerFormField, payload []byte) error {
	if field.Policy != "" && field.Signature != "" {
		return c.uploadStickerS3(ctx, field, payload)
	}
	return c.uploadStickerEmbeddedCDN(ctx, field, payload)
}

// uploadStickerS3 POSTs the payload to the S3 bucket configured on the
// signal server, embedding every policy field per the AWS SigV4 spec.
func (c *Client) uploadStickerS3(ctx context.Context, field stickers.StickerFormField, payload []byte) error {
	body := &bytes.Buffer{}
	mw := multipart.NewWriter(body)

	for _, kv := range [][2]string{
		{"key", field.Key},
		{"acl", field.Acl},
		{"x-amz-algorithm", field.Algorithm},
		{"x-amz-credential", field.Credential},
		{"x-amz-date", field.Date},
		{"policy", field.Policy},
		{"x-amz-signature", field.Signature},
	} {
		if kv[1] == "" {
			continue
		}
		if err := mw.WriteField(kv[0], kv[1]); err != nil {
			return signalerrors.Wrap(signalerrors.ErrInternal, "multipart field "+kv[0], err)
		}
	}
	fw, err := mw.CreateFormFile("file", field.Key)
	if err != nil {
		return signalerrors.Wrap(signalerrors.ErrInternal, "multipart file", err)
	}
	if _, err := fw.Write(payload); err != nil {
		return signalerrors.Wrap(signalerrors.ErrInternal, "multipart write", err)
	}
	if err := mw.Close(); err != nil {
		return signalerrors.Wrap(signalerrors.ErrInternal, "multipart close", err)
	}

	if field.BucketEndpoint == "" {
		return signalerrors.New(signalerrors.ErrInternal, "upload form has S3 policy but no BucketEndpoint — server misconfigured")
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, field.BucketEndpoint, body)
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", mw.FormDataContentType())
	resp, err := c.httpClient.Do(req)
	if err != nil {
		return err
	}
	defer func() { _ = resp.Body.Close() }()
	// S3 returns 204 No Content on a successful POST policy upload.
	// 200 is also accepted as a defensive measure (some compatible
	// gateways return 200). Anything else — including 3xx redirects
	// (which suggest a proxy intercepting), 1xx, or 4xx/5xx — is a
	// failure: surface it with the response body so operators have
	// the S3 error text to debug.
	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusNoContent {
		respBody, _ := io.ReadAll(resp.Body)
		return &APIError{StatusCode: resp.StatusCode, Message: string(respBody)}
	}
	return nil
}

// uploadStickerEmbeddedCDN handles the dev/single-node fallback path
// where the signal server's own /cdn3 endpoint accepts a raw PUT.
func (c *Client) uploadStickerEmbeddedCDN(ctx context.Context, field stickers.StickerFormField, payload []byte) error {
	loc := field.Location
	if loc == "" {
		return signalerrors.New(signalerrors.ErrInternal, "upload form field for "+strconv.Quote(field.Key)+" has no Location and no S3 policy")
	}
	endpoint := loc
	if strings.HasPrefix(loc, "/") {
		endpoint = c.config.ServerURL + loc
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPut, endpoint, bytes.NewReader(payload))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/octet-stream")
	for k, v := range field.Headers {
		req.Header.Set(k, v)
	}
	resp, err := c.httpClient.Do(req)
	if err != nil {
		return err
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusNoContent {
		respBody, _ := io.ReadAll(resp.Body)
		return &APIError{StatusCode: resp.StatusCode, Message: string(respBody)}
	}
	return nil
}
