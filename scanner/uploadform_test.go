package scanner

import (
	"strings"
	"testing"
)

func TestParseUploadFormFieldsCTFHubStyle(t *testing.T) {
	body := `<html><body>
<form action="" method="post" enctype="multipart/form-data">
    <input type="file" name="file" />
    <input type="submit" name="submit" value="Submit" />
</form>
</body></html>`
	form := ParseUploadFormFields(body)
	if form.FileField != "file" {
		t.Fatalf("FileField = %q, want file", form.FileField)
	}
	if got := form.Extra["submit"]; got != "Submit" {
		t.Fatalf("submit = %q, want Submit", got)
	}
	if len(form.Extra) != 1 {
		t.Fatalf("Extra = %v, want only submit", form.Extra)
	}
}

func TestParseUploadFormFieldsMixedControls(t *testing.T) {
	body := `<form method="POST" enctype="multipart/form-data" action="/upload">
<input type=file name=upfile>
<input type="hidden" name="csrf_token" value="abc123">
<input type="text" name="title" value="hi">
<input type="checkbox" name="agree" value="1" checked>
<input type="checkbox" name="newsletter" value="1">
<input type="radio" name="scope" value="public" checked>
<input type="password" name="pin" value="">
<input type="submit" name="go" value="Upload" disabled>
<button type="submit" name="btn" value="x">go</button>
<input type="file" name="second">
</form>`
	form := ParseUploadFormFields(body)
	if form.FileField != "upfile" {
		t.Fatalf("FileField = %q, want upfile", form.FileField)
	}
	want := map[string]string{
		"csrf_token": "abc123",
		"title":      "hi",
		"agree":      "1",
		"scope":      "public",
		"pin":        "",
	}
	if len(form.Extra) != len(want) {
		t.Fatalf("Extra = %v, want %v", form.Extra, want)
	}
	for k, v := range want {
		if got := form.Extra[k]; got != v {
			t.Fatalf("Extra[%q] = %q, want %q", k, got, v)
		}
	}
}

func TestParseUploadFormFieldsSkipsNonUploadForms(t *testing.T) {
	body := `<form action="/search"><input name="q"></form>
<form action="/login"><input type="password" name="pw"><input type="submit" name="submit"></form>
<form action="/upload" method="post" enctype="multipart/form-data">
  <input type="file" name="file">
  <input type="submit" name="submit" value="Submit">
</form>`
	form := ParseUploadFormFields(body)
	if form.FileField != "file" || form.Extra["submit"] != "Submit" {
		t.Fatalf("form = %+v, want upload form", form)
	}
}

func TestParseUploadFormFieldsNoForm(t *testing.T) {
	form := ParseUploadFormFields(`<html><body><input type="file" name="file"></body></html>`)
	if form.FileField != "" || len(form.Extra) != 0 {
		t.Fatalf("form = %+v, want empty", form)
	}
}

func TestMergeUploadFormFields(t *testing.T) {
	form := UploadFormFields{
		FileField: "upfile",
		Extra:     map[string]string{"submit": "Submit", "csrf_token": "tok"},
	}

	// The default placeholder "file" is corrected by detection.
	name, extra, added := MergeUploadFormFields("file", map[string]string{"submit": "Go"}, form)
	if name != "upfile" {
		t.Fatalf("name = %q, want upfile", name)
	}
	if extra["submit"] != "Go" {
		t.Fatalf("explicit submit overridden: %v", extra)
	}
	if extra["csrf_token"] != "tok" {
		t.Fatalf("detected csrf_token missing: %v", extra)
	}
	if strings.Join(added, ",") != "csrf_token" {
		t.Fatalf("added = %v, want [csrf_token]", added)
	}

	// An explicit non-default field name is respected.
	name, _, _ = MergeUploadFormFields("attachment", nil, form)
	if name != "attachment" {
		t.Fatalf("name = %q, want explicit attachment", name)
	}

	// No detected file input: raw mode (empty field) survives.
	name, _, _ = MergeUploadFormFields("", nil, UploadFormFields{})
	if name != "" {
		t.Fatalf("name = %q, want raw empty", name)
	}
}
