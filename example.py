import subprocess

def getContext():
    context = input("What is the context (Option: authorization): ")
    return context        


def getId():
    requesterId = input("Spiffe ID: ")
    requestMethod = input("Request Method: ")
    with open('example.rego','w') as out:
        line1 = "package envoy.authz\n"
        line2 = "import input.attributes.request.http as http_request\n\n"
        line3 = "default allow = false\n"
        line4 = "allow {\n"
        line5 = "   valid_path\n"
        line6 = '   http_request.method == "%s"\n' %(requestMethod)
        line7 = '   svc_spiffe_id == "%s"\n' %(requesterId)
        line8 = "}\n\n"
        out.writelines([line1, line2, line3, line4, line5, line6, line7, line8])

def getCertInfo():
    with open('example.rego', 'a') as out:
        line1 = "svc_spiffe_id = spiffe_id {\n"
        line2 = '  [_, _, uri_type_san] := split(http_request.headers["x-forwarded-client-cert"], ";")\n'
        line3 = '  [_, spiffe_id] := split(uri_type_san, "=")\n'
        line4 = "}\n\n"
        out.writelines([line1, line2, line3, line4])


def getPaths():
    paths = input("Give me the different paths as a comma delimited list: ")
    parsedPath = paths.split(',')
    with open('example.rego', 'a') as out:
        for path in parsedPath: 
            line1 = "valid_path {\n"
            line2 = '   glob.match("/%s/*", [], http_request.path)\n' %(path)
            line3 = "}\n"
            out.writelines([line1, line2, line3])
    print("[** Created example.rego")

def passPolicyEnvoy():
    old = "example.rego"
    new = "/home/venafi_cmu/Spire-kubernetes/k8s/envoy-opa/k8s/backend/config/opa-policy-test.rego"
    subprocess.run("mv %s %s" %(old, new), shell=True)
    # subprocess.run(("scp -i %s example.rego %s@%s:.") %(path, user, externalIp), shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE).communicate()
    print("[** Pushed example.rego file to envoy proxy and renamed opa-policy-test.rego**]")

    

if __name__ == "__main__":
    if getContext() == "authorization":
        getId()
        getCertInfo()
        getPaths()
        passPolicyEnvoy()