package envoy.authz
import input.attributes.request.http as http_request

default allow = false
allow {
   valid_path
   http_request.method == "New Method"
   svc_spiffe_id == "NEW ID"
}

svc_spiffe_id = spiffe_id {
  [_, _, uri_type_san] := split(http_request.headers["x-forwarded-client-cert"], ";")
  [_, spiffe_id] := split(uri_type_san, "=")
}

valid_path {
   glob.match("/new/*", [], http_request.path)
}
valid_path {
   glob.match("/list/*", [], http_request.path)
}
valid_path {
   glob.match("/aa/*", [], http_request.path)
}
