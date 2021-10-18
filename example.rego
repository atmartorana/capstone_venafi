package envoy.authz
import input.attributes.request.http as http_request

default allow = false
allow {
   valid_path
   http_request.method == "asdf"
   svc_spiffe_id == "asdfsad"
}

svc_spiffe_id = spiffe_id {
  [_, _, uri_type_san] := split(http_request.headers["x-forwarded-client-cert"], ";")
  [_, spiffe_id] := split(uri_type_san, "=")
}

valid_path {
   glob.match("/sf/*", [], http_request.path)
}
valid_path {
   glob.match("/fds/*", [], http_request.path)
}
valid_path {
   glob.match("/asd/*", [], http_request.path)
}
valid_path {
   glob.match("/f/*", [], http_request.path)
}
