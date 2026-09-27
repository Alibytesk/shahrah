set -e
here=$(cd "$(dirname "$0")" && pwd)
cd "$here/.."
cargo build --release -p shahrah-proxy
cp target/release/shahrah-proxy "$here/shahrah-proxy"
cd "$here"
docker compose build --quiet
docker compose up -d --wait
python3 harness.py "$@"
