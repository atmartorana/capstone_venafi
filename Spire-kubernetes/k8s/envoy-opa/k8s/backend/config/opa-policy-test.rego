package envoy.authz
import input.attributes.request.http as http_request

default allow = false
allow {
   valid_path
   http_request.method == "POST"
   svc_spiffe_id == "spire://asdfasdfasdf"
}

svc_spiffe_id = spiffe_id {
  [_, _, uri_type_san] := split(http_request.headers["x-forwarded-client-cert"], ";")
  [_, spiffe_id] := split(uri_type_san, "=")
}

valid_path {
   glob.match("/bla/*", [], http_request.path)
}
valid_path {
   glob.match("/blahh/*", [], http_request.path)
}
valid_path {
   glob.match("/blah/*", [], http_request.path)
}
