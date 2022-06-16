import json
import os
import urllib.request as request

def versions(package_name):
    url = "https://pypi.org/pypi/%s/json" % (package_name,)
    data = json.load(request.urlopen(url))
    versions = sorted(data["releases"].keys(), reverse=True)
    return versions

def vulnerable(package_name, version):
    body = {
        "version": version,
        "package": {
            "name": package_name, 
            "ecosystem": "PyPI"
            }
        }
    headers = {
        "Content-Type": "application/json",
        "Accept": "application/json",
        }

    data = json.dumps(body).encode("utf-8")
    url = "https://api.osv.dev/v1/query"

    req = request.Request(url, data, headers)
    response = request.urlopen(req)

    with response as f:
        return json.loads(f.read().decode())

path = os.path.dirname(os.path.abspath(__file__))

try:
    vulnerable_packages = []

    file = open(path + "/scan_results.json")
    output = json.load(file)

    for package in output["results"]:
        name = package["extra"]["metavars"]["$1"]["abstract_content"]
        qualifier = package["extra"]["metavars"]["$2"]["abstract_content"]
        version = package["extra"]["metavars"]["$3"]["abstract_content"]

        try:
            available_versions = versions(name)
            used_versions = None

            if qualifier == ">":
                used_versions = available_versions.filter(lambda v: v > version)
            elif qualifier == "<":
                used_versions = available_versions.filter(lambda v: v < version)
            elif qualifier == ">=":
                used_versions = available_versions.filter(lambda v: v >= version)
            elif qualifier == "<=":
                used_versions = available_versions.filter(lambda v: v <= version)
            elif qualifier == "==":
                if version in available_versions:
                    used_versions = [version]
            elif qualifier == "~=":
                for available_version in available_versions:
                    if available_version > version:
                        used_versions.append(available_version)
            else:
                print("Unknown qualifier: " + qualifier)
                pass

            for used_version in used_versions:
                vulnerable_response = vulnerable(name, used_version)
                if len(vulnerable_response) > 0:
                    vulnerable_packages.append(name + ": " + str(used_version))
            
        except Exception as e:
            print("Package " + name + " not on PyPi.")
except Exception as e:
    print(e)

print(vulnerable_packages)

