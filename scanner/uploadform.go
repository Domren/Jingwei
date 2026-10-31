package scanner

import (
	"regexp"
	"sort"
	"strings"
)

// uploadMaxFormChunk bounds how much of one <form> body we scan for fields.
// Upload forms are small; the cap only guards against pathological pages.
const uploadMaxFormChunk = 64 << 10

var (
	reUploadInput    = regexp.MustCompile(`(?is)<input\b([^>]*)>`)
	reUploadDisabled = regexp.MustCompile(`(?i)\bdisabled\b`)
	reUploadChecked  = regexp.MustCompile(`(?i)\bchecked\b`)
)

// UploadFormFields is the named control set a browser would submit together
// with the file input of an upload form.
type UploadFormFields struct {
	// FileField is the name attribute of the form's <input type=file>.
	FileField string
	// Extra maps every other named control to the value a browser would send.
	Extra map[string]string
}

// ParseUploadFormFields scans a page for the first <form> that contains a file
// input and rebuilds the field set a browser would submit with it. Upload
// handlers frequently gate on these controls: legacy PHP scripts only process
// the file when the submit button field is present, and CSRF-protected forms
// reject uploads without their hidden token.
func ParseUploadFormFields(body string) UploadFormFields {
	out := UploadFormFields{Extra: map[string]string{}}
	for _, span := range reHarvestForm.FindAllStringIndex(body, maxHarvestForms) {
		chunk := body[span[1]:]
		if i := indexFold(chunk, "</form>"); i >= 0 && i <= len(chunk) {
			chunk = chunk[:i]
		}
		if len(chunk) > uploadMaxFormChunk {
			chunk = chunk[:uploadMaxFormChunk]
		}
		fields, fileField, hasFile := parseUploadChunk(chunk)
		if !hasFile {
			continue
		}
		out.FileField = fileField
		out.Extra = fields
		return out
	}
	return out
}

func parseUploadChunk(chunk string) (map[string]string, string, bool) {
	fields := map[string]string{}
	fileField, hasFile := "", false
	for _, m := range reUploadInput.FindAllStringSubmatch(chunk, maxHarvestFields) {
		raw := m[1]
		attrs := harvestAttrs(raw)
		name := strings.TrimSpace(attrs["name"])
		switch strings.ToLower(strings.TrimSpace(attrs["type"])) {
		case "file":
			// A nameless file input still marks the form as an upload form.
			if !hasFile {
				fileField, hasFile = name, true
			}
		case "checkbox", "radio":
			// Unchecked boxes are not submitted by browsers, and an empty value
			// could overwrite a server-side default the handler expects.
			if name == "" || reUploadDisabled.MatchString(raw) || !reUploadChecked.MatchString(raw) {
				continue
			}
			fields[name] = firstNonEmpty(attrs["value"], "on")
		case "submit":
			if name == "" || reUploadDisabled.MatchString(raw) {
				continue
			}
			fields[name] = firstNonEmpty(attrs["value"], "Submit")
		case "button", "image", "reset":
			// Browser-submitted only via scripting; never part of a plain POST.
		case "password":
			if name == "" || reUploadDisabled.MatchString(raw) {
				continue
			}
			fields[name] = attrs["value"]
		default:
			// text/hidden/search/email/...: submit the declared (often empty)
			// value, exactly like a browser would.
			if name == "" || reUploadDisabled.MatchString(raw) {
				continue
			}
			fields[name] = attrs["value"]
		}
	}
	return fields, fileField, hasFile
}

// MergeUploadFormFields decides the effective file field name and the extra
// form fields of an upload request. Explicit values from the task/LLM always
// win; detected fields only fill the gaps. The documented default "file" is
// treated as a placeholder so a page that names its input differently still
// gets the right field. The returned slice lists the detected keys that were
// added, sorted, for logging.
func MergeUploadFormFields(fieldName string, explicit map[string]string, form UploadFormFields) (string, map[string]string, []string) {
	merged := map[string]string{}
	for k, v := range explicit {
		merged[k] = v
	}
	added := []string{}
	for k, v := range form.Extra {
		if hasFieldFold(merged, k) {
			continue
		}
		merged[k] = v
		added = append(added, k)
	}
	sort.Strings(added)
	if form.FileField != "" && (fieldName == "" || (fieldName == "file" && !strings.EqualFold(form.FileField, "file"))) {
		fieldName = form.FileField
	}
	return fieldName, merged, added
}

func hasFieldFold(m map[string]string, key string) bool {
	for k := range m {
		if strings.EqualFold(k, key) {
			return true
		}
	}
	return false
}
