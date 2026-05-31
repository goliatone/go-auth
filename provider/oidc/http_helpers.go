package oidc

import "io"

func closeBody(body io.Closer) {
	_ = body.Close()
}
